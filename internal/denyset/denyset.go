// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package denyset parses, validates and diffs the declarative leased-deny file
// (format "netra-denyset/1"). It is pure: it never reads controller state and
// never applies anything. Every rule carries a lease, so a file cannot create a
// permanent rule.
package denyset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Version is the required first line of a file.
const Version = "netra-denyset/1"

// Bounds on hostile input.
const (
	MaxFileBytes = 64 << 10
	MaxLineBytes = 512
	MaxRules     = 500
	MaxErrors    = 50
	MinLease     = time.Minute
	MaxLease     = 24 * time.Hour
)

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)

// Rule is one deny rule. Type is the store rule index type ("cidr" or "port").
type Rule struct {
	Type         string `json:"type"`
	CIDR         string `json:"cidr,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Direction    string `json:"direction"`
	LeaseSeconds int64  `json:"leaseSeconds"`
	Line         int    `json:"line,omitempty"`
	// Kind is the keyword used in the file ("cidr", "ip" or "port"); it picks
	// the deny-preview kind. An "ip" rule is stored as a /32 or /128 CIDR.
	Kind string `json:"kind"`
}

// Key is the store rule index key (without the type prefix).
func (r Rule) Key() string {
	if r.Type == "port" {
		return r.Direction + "|" + r.Protocol + "|" + strconv.FormatUint(uint64(r.Port), 10)
	}
	return r.Direction + "|" + r.CIDR
}

// Summary is a human readable rule.
func (r Rule) Summary() string {
	if r.Type == "port" {
		return fmt.Sprintf("%s · %s/%d", r.Direction, r.Protocol, r.Port)
	}
	return r.Direction + " · " + r.CIDR
}

// File is a parsed denyset.
type File struct {
	Name         string `json:"name"`
	LeaseSeconds int64  `json:"leaseSeconds"` // file default
	Rules        []Rule `json:"rules"`
}

// ParseError is one line-numbered validation error.
type ParseError struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

func (e ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Message) }

// Parse reads a denyset. All errors (up to MaxErrors) are returned together.
func Parse(data []byte) (*File, []ParseError) {
	var errs []ParseError
	add := func(line int, f string, a ...any) {
		if len(errs) < MaxErrors {
			errs = append(errs, ParseError{Line: line, Message: fmt.Sprintf(f, a...)})
		}
	}
	if len(data) > MaxFileBytes {
		return nil, []ParseError{{Line: 0, Message: fmt.Sprintf("file is %d bytes; the limit is %d", len(data), MaxFileBytes)}}
	}
	if !utf8.Valid(data) {
		return nil, []ParseError{{Line: 0, Message: "file is not valid UTF-8"}}
	}
	f := &File{}
	seen := map[string]int{}
	sawVersion, sawName, sawLease := false, false, false
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		if len(raw) > MaxLineBytes {
			add(n, "line is %d bytes; the limit is %d", len(raw), MaxLineBytes)
			continue
		}
		line := strings.TrimRight(raw, "\r")
		if j := strings.Index(line, "#"); j >= 0 {
			line = line[:j]
		}
		bad := false
		for _, c := range line {
			if c != '\t' && unicode.IsControl(c) {
				add(n, "control character not allowed")
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !sawVersion {
			if line != Version {
				add(n, "first line must be %q", Version)
				return nil, errs
			}
			sawVersion = true
			continue
		}
		fields := strings.Fields(line)
		switch {
		case fields[0] == "name:":
			if sawName {
				add(n, "duplicate name")
			} else if len(fields) != 2 || !nameRe.MatchString(fields[1]) {
				add(n, "name must be one token of lowercase letters, digits and '-' (1-42 chars, alphanumeric ends)")
			} else {
				f.Name = fields[1]
			}
			sawName = true
		case fields[0] == "lease:":
			if sawLease {
				add(n, "duplicate lease")
			} else if len(fields) != 2 {
				add(n, "lease must be one duration such as 30m")
			} else if d, err := parseLease(fields[1]); err != nil {
				add(n, "%v", err)
			} else {
				f.LeaseSeconds = int64(d / time.Second)
			}
			sawLease = true
		case fields[0] == "deny":
			if len(f.Rules) >= MaxRules {
				add(n, "more than %d rules", MaxRules)
				continue
			}
			r, err := parseRule(fields[1:])
			if err != nil {
				add(n, "%v", err)
				continue
			}
			r.Line = n
			if first, dup := seen[r.Type+"|"+r.Key()]; dup {
				add(n, "duplicate of the rule on line %d", first)
				continue
			}
			seen[r.Type+"|"+r.Key()] = n
			f.Rules = append(f.Rules, r)
		default:
			add(n, "unknown directive %q (expected name:, lease: or deny)", truncate(fields[0], 40))
		}
	}
	if !sawVersion {
		return nil, []ParseError{{Line: 1, Message: fmt.Sprintf("missing %q header", Version)}}
	}
	if !sawName {
		add(1, "name: is required (it labels the leases this file owns)")
	}
	if !sawLease {
		add(1, "lease: is required (a denyset cannot create a permanent rule)")
	}
	if len(errs) > 0 {
		return nil, errs
	}
	// Apply the file default lease to rules without their own.
	for i := range f.Rules {
		if f.Rules[i].LeaseSeconds == 0 {
			f.Rules[i].LeaseSeconds = f.LeaseSeconds
		}
	}
	sort.Slice(f.Rules, func(a, b int) bool {
		if f.Rules[a].Type != f.Rules[b].Type {
			return f.Rules[a].Type < f.Rules[b].Type
		}
		return f.Rules[a].Key() < f.Rules[b].Key()
	})
	return f, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func parseLease(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("lease %q is not a duration", truncate(v, 40))
	}
	if d < MinLease || d > MaxLease {
		return 0, fmt.Errorf("lease %s must be between %s and %s", d, MinLease, MaxLease)
	}
	return d, nil
}

func parseDirection(v string) (string, error) {
	switch v {
	case "egress", "ingress", "both":
		return v, nil
	}
	return "", fmt.Errorf("direction must be egress, ingress or both, got %q", truncate(v, 40))
}

// parseRule handles the tokens after "deny". Options (lease=) come last.
func parseRule(tok []string) (Rule, error) {
	var lease int64
	pos := tok
	for i, t := range tok {
		if strings.Contains(t, "=") {
			pos = tok[:i]
			for _, o := range tok[i:] {
				k, v, ok := strings.Cut(o, "=")
				if !ok || k != "lease" {
					return Rule{}, fmt.Errorf("unknown option %q (only lease=DURATION)", truncate(o, 40))
				}
				if lease != 0 {
					return Rule{}, fmt.Errorf("duplicate lease option")
				}
				d, err := parseLease(v)
				if err != nil {
					return Rule{}, err
				}
				lease = int64(d / time.Second)
			}
			break
		}
	}
	if len(pos) == 0 {
		return Rule{}, fmt.Errorf("deny needs a kind: cidr, ip or port")
	}
	r := Rule{LeaseSeconds: lease, Kind: pos[0]}
	switch pos[0] {
	case "cidr", "ip":
		if len(pos) != 3 {
			return Rule{}, fmt.Errorf("usage: deny %s VALUE egress|ingress|both [lease=D]", pos[0])
		}
		dir, err := parseDirection(pos[2])
		if err != nil {
			return Rule{}, err
		}
		r.Type, r.Direction = "cidr", dir
		if pos[0] == "ip" {
			a, err := netip.ParseAddr(pos[1])
			if err != nil || a.Zone() != "" {
				return Rule{}, fmt.Errorf("invalid IP %q", truncate(pos[1], 60))
			}
			a = a.Unmap()
			r.CIDR = netip.PrefixFrom(a, a.BitLen()).String()
		} else {
			p, err := netip.ParsePrefix(pos[1])
			if err != nil {
				return Rule{}, fmt.Errorf("invalid CIDR %q", truncate(pos[1], 60))
			}
			r.CIDR = p.Masked().String()
		}
	case "port":
		if len(pos) != 4 {
			return Rule{}, fmt.Errorf("usage: deny port tcp|udp|any PORT egress|ingress|both [lease=D]")
		}
		proto := strings.ToUpper(pos[1])
		if proto != "TCP" && proto != "UDP" && proto != "ANY" {
			return Rule{}, fmt.Errorf("protocol must be tcp, udp or any")
		}
		n, err := strconv.ParseUint(pos[2], 10, 16)
		if err != nil || n == 0 {
			return Rule{}, fmt.Errorf("port must be 1-65535")
		}
		dir, err := parseDirection(pos[3])
		if err != nil {
			return Rule{}, err
		}
		r.Type, r.Protocol, r.Port, r.Direction = "port", proto, uint16(n), dir
	default:
		return Rule{}, fmt.Errorf("unknown deny kind %q (cidr, ip or port)", truncate(pos[0], 40))
	}
	return r, nil
}

// Actions of a plan item.
const (
	ActionAdd       = "add"
	ActionExtend    = "extend"
	ActionRemove    = "remove"
	ActionUnchanged = "unchanged"
	ActionSkip      = "skip" // rule exists but is not owned by this denyset; never touched
)

// Existing describes what the controller holds for one rule key.
type Existing struct {
	Owner        string // lease owner; empty when the rule has no lease
	LeaseSeconds int64
}

// Item is one plan line.
type Item struct {
	Action       string `json:"action"`
	Type         string `json:"type"`
	Key          string `json:"key"`
	Summary      string `json:"summary"`
	LeaseSeconds int64  `json:"leaseSeconds,omitempty"`
	PrevLease    int64  `json:"previousLeaseSeconds,omitempty"`
	Note         string `json:"note,omitempty"`
	Rule         *Rule  `json:"rule,omitempty"`
}

// Lease is a lease currently owned by a denyset (input to Diff).
type Lease struct {
	Owner        string
	Type, Key    string
	Summary      string
	LeaseSeconds int64
}

// Diff computes the plan. leases are all current denyset leases (any owner);
// present is the set of "type|key" for every rule currently in the config.
// Removals only ever come from leases owned by f.Name.
func Diff(f *File, leases []Lease, present map[string]bool) []Item {
	byKey := map[string]Lease{}
	for _, l := range leases {
		byKey[l.Type+"|"+l.Key] = l
	}
	var items []Item
	want := map[string]bool{}
	for i := range f.Rules {
		r := f.Rules[i]
		ck := r.Type + "|" + r.Key()
		want[ck] = true
		it := Item{Type: r.Type, Key: r.Key(), Summary: r.Summary(), LeaseSeconds: r.LeaseSeconds, Rule: &r}
		l, leased := byKey[ck]
		switch {
		case leased && l.Owner == f.Name:
			it.PrevLease = l.LeaseSeconds
			if l.LeaseSeconds != r.LeaseSeconds {
				it.Action = ActionExtend
			} else {
				it.Action = ActionUnchanged
			}
		case leased:
			it.Action, it.Note = ActionSkip, "leased by denyset "+l.Owner
		case present[ck]:
			it.Action, it.Note = ActionSkip, "rule exists without a lease; a denyset never takes over or deletes it"
		default:
			it.Action = ActionAdd
		}
		items = append(items, it)
	}
	for _, l := range leases {
		if l.Owner != f.Name || want[l.Type+"|"+l.Key] {
			continue
		}
		items = append(items, Item{Action: ActionRemove, Type: l.Type, Key: l.Key, Summary: l.Summary, PrevLease: l.LeaseSeconds})
	}
	order := map[string]int{ActionAdd: 0, ActionExtend: 1, ActionRemove: 2, ActionUnchanged: 3, ActionSkip: 4}
	sort.Slice(items, func(a, b int) bool {
		if order[items[a].Action] != order[items[b].Action] {
			return order[items[a].Action] < order[items[b].Action]
		}
		if items[a].Type != items[b].Type {
			return items[a].Type < items[b].Type
		}
		return items[a].Key < items[b].Key
	})
	return items
}

// Hash is the stable plan hash: it covers the name and every item's action,
// rule and lease, never a time or a line number.
func Hash(name string, items []Item) string {
	type h struct {
		A, T, K string
		L, P    int64
	}
	out := make([]h, len(items))
	for i, it := range items {
		out[i] = h{it.Action, it.Type, it.Key, it.LeaseSeconds, it.PrevLease}
	}
	b, _ := json.Marshal(struct {
		V string
		N string
		I []h
	}{Version, name, out})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Counts summarises items by action.
func Counts(items []Item) map[string]int {
	m := map[string]int{ActionAdd: 0, ActionExtend: 0, ActionRemove: 0, ActionUnchanged: 0, ActionSkip: 0}
	for _, it := range items {
		m[it.Action]++
	}
	return m
}
