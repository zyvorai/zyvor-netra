// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Package securityreview builds review-only proposals from config and metadata.
package securityreview

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/zyvorai/netra/internal/models"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Rule struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Value          string `json:"value"`
	Direction      string `json:"direction"`
	Protocol       string `json:"protocol"`
	SynOnly        bool   `json:"synOnly"`
	MatchingEvents int    `json:"matchingEvents"`
}
type Suggestion struct {
	Kind        string `json:"kind"`
	Rule        string `json:"rule"`
	RelatedRule string `json:"relatedRule"`
	Message     string `json:"message"`
}
type Optimization struct {
	TotalRules  int          `json:"totalRules"`
	Rules       []Rule       `json:"rules"`
	Suggestions []Suggestion `json:"suggestions"`
	Truncated   bool         `json:"truncated"`
	AutoApplied bool         `json:"autoApplied"`
	Note        string       `json:"note"`
}

func stableID(v any) string { b, _ := json.Marshal(v); return fmt.Sprintf("%x", sha256.Sum256(b))[:20] }
func direction(d string) string {
	if d == "" {
		return "egress"
	}
	return d
}
func dirCovers(a, b string) bool { return a == "both" || a == b }
func rules(c models.EBPFFastPathConfig) []Rule {
	out := []Rule{}
	add := func(t, v, d, p string, syn bool) {
		r := Rule{Type: t, Value: v, Direction: d, Protocol: p, SynOnly: syn}
		r.ID = stableID([]any{t, v, d, p, syn, len(out)})
		out = append(out, r)
	}
	synIP := func(v, d string) bool {
		for _, s := range c.SynDrop {
			if s.Address == v && s.Direction == d {
				return true
			}
		}
		return false
	}
	for _, group := range []struct {
		ips []string
		dir string
	}{{c.BlockedIPv4, "egress"}, {c.BlockedIPv6, "egress"}, {c.BlockedIngressIPv4, "ingress"}, {c.BlockedIngressIPv6, "ingress"}} {
		for _, v := range group.ips {
			if a, err := netip.ParseAddr(v); err == nil {
				add("ip", a.Unmap().String(), group.dir, "ANY", synIP(v, group.dir))
			}
		}
	}
	for _, r := range c.BlockedCIDRs {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			continue
		}
		dirs := []string{direction(r.Direction)}
		if dirs[0] == "both" {
			dirs = []string{"egress", "ingress"}
		}
		for _, d := range dirs {
			syn := false
			for _, s := range c.SynDropCIDR {
				q, e := netip.ParsePrefix(s.CIDR)
				if e == nil && q.Masked() == p.Masked() && s.Direction == d {
					syn = true
				}
			}
			add("cidr", p.Masked().String(), d, "ANY", syn)
		}
	}
	for _, r := range c.BlockedPorts {
		p := strings.ToUpper(r.Protocol)
		if p == "" {
			p = "ANY"
		}
		add("port", strconv.Itoa(int(r.Port)), direction(r.Direction), p, false)
	}
	return out
}
func prefix(r Rule) (netip.Prefix, bool) {
	if r.Type == "cidr" {
		p, e := netip.ParsePrefix(r.Value)
		return p, e == nil
	}
	if r.Type == "ip" {
		a, e := netip.ParseAddr(r.Value)
		if e == nil {
			return netip.PrefixFrom(a, a.BitLen()), true
		}
	}
	return netip.Prefix{}, false
}
func covers(a, b Rule) bool {
	if !dirCovers(a.Direction, b.Direction) || (a.SynOnly && !b.SynOnly) {
		return false
	}
	if a.Type == "port" || b.Type == "port" {
		return a.Type == "port" && b.Type == "port" && a.Value == b.Value && (a.Protocol == "ANY" || a.Protocol == b.Protocol)
	}
	x, ok := prefix(a)
	y, ok2 := prefix(b)
	return ok && ok2 && x.Addr().BitLen() == y.Addr().BitLen() && x.Bits() <= y.Bits() && x.Contains(y.Addr())
}
func matches(r Rule, e models.FastPathEvent) bool {
	if !dirCovers(r.Direction, e.Direction) {
		return false
	}
	if r.SynOnly && e.Protocol == "TCP" && (e.Hook == "cgroup" || e.Hook == "tc") && (e.TCPFlags&2 == 0 || e.TCPFlags&16 != 0) {
		return false
	}
	if r.Type == "port" {
		port := e.DestinationPort

		return strconv.Itoa(int(port)) == r.Value && (r.Protocol == "ANY" || r.Protocol == e.Protocol)
	}
	ip := e.DestinationIP
	if e.Direction == "ingress" {
		ip = e.SourceIP
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	p, ok := prefix(r)
	return ok && p.Contains(a.Unmap())
}
func Optimize(c models.EBPFFastPathConfig, agents []models.AgentStatus, now time.Time) Optimization {
	out := Optimization{Rules: rules(c), Suggestions: []Suggestion{}, Note: "Review only: matching sampled events are not rule-hit counters. Allow exceptions, workload scope, native NetPol, hook order and enforcement lease may change the outcome. No unused-rule claim or automatic deletion."}
	out.TotalRules = len(out.Rules)
	if len(out.Rules) > 1000 {
		out.Rules = out.Rules[:1000]
		out.Truncated = true
	}
	for i := range out.Rules {
		for _, a := range agents {
			if a.Stale {
				continue
			}
			for _, e := range a.Events {
				if recent(e.ObservedAt, now) && matches(out.Rules[i], e) {
					out.Rules[i].MatchingEvents++
				}
			}
		}
	}
	// Configuration can contain thousands of entries. Bound review work and output.
	checked := out.Rules
	if len(checked) > 1000 {
		checked = checked[:1000]
		out.Truncated = true
	}
	for i, a := range checked {
		for j := i + 1; j < len(checked); j++ {
			b := checked[j]
			kind, rule, related := "", "", ""
			switch {
			case covers(a, b) && covers(b, a):
				kind = "equivalent"
				rule = b.ID
				related = a.ID
			case covers(a, b):
				kind = "covered"
				rule = b.ID
				related = a.ID
			case covers(b, a):
				kind = "covered"
				rule = a.ID
				related = b.ID
			default:
				x, ok := prefix(a)
				y, ok2 := prefix(b)
				if ok && ok2 && a.Direction == b.Direction && x.Addr().BitLen() == y.Addr().BitLen() && x.Overlaps(y) {
					kind = "overlap"
					rule = a.ID
					related = b.ID
				}
			}
			if kind != "" {
				out.Suggestions = append(out.Suggestions, Suggestion{Kind: kind, Rule: rule, RelatedRule: related, Message: "Compare these flat deny predicates before changing configuration; this is not a policy precedence proof."})
			}
			if len(out.Suggestions) >= 200 {
				out.Truncated = true
				return out
			}
		}
	}
	return out
}
func recent(at, now time.Time) bool {
	return !at.IsZero() && !at.After(now) && !at.Before(now.Add(-10*time.Minute))
}
