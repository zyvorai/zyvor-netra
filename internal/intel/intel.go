// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package intel parses an operator-supplied threat-intel or allow/deny
// list into the same entry shape POST /api/v1/ebpf/deny/import already
// accepts. Preview is pure and apply-nothing; the API layer may later
// feed accepted entries through the existing import handler.
package intel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

const MaxEntries = 1000

// Entry matches internal/api denyImportEntry JSON so a preview result can
// be pasted straight into the existing import endpoint.
type Entry struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Direction string `json:"direction,omitempty"`
}

type Issue struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type Preview struct {
	Entries []Entry `json:"entries"`
	Skipped []Issue `json:"skipped"`
	Count   int     `json:"count"`
	Dropped int     `json:"dropped"`
}

// Parse accepts JSON ({"entries":[...]} or a raw array), CSV
// (type,value,direction), or a plain newline list of IPs/CIDRs/names.
// Comments (#) and blank lines are ignored. Never mutates anything.
func Parse(raw string) (Preview, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Preview{}, fmt.Errorf("input is empty")
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return parseJSON(trimmed)
	}
	return parseLines(trimmed), nil
}

func parseJSON(raw string) (Preview, error) {
	var wrap struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.Unmarshal([]byte(raw), &wrap); err == nil && wrap.Entries != nil {
		return normalize(wrap.Entries), nil
	}
	var arr []Entry
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return Preview{}, fmt.Errorf("intel JSON: %w", err)
	}
	return normalize(arr), nil
}

func parseLines(raw string) Preview {
	var pending []Entry
	sc := bufio.NewScanner(strings.NewReader(raw))
	line := 0
	var skipped []Issue
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
			continue
		}
		e, err := parseLine(s)
		if err != nil {
			skipped = append(skipped, Issue{Line: line, Message: err.Error()})
			continue
		}
		pending = append(pending, e)
	}
	if err := sc.Err(); err != nil {
		skipped = append(skipped, Issue{Line: line + 1, Message: "input line too long"})
	}
	out := normalize(pending)
	out.Skipped = append(skipped, out.Skipped...)
	out.Dropped = len(out.Skipped)
	return out
}

func parseLine(s string) (Entry, error) {
	// CSV: type,value[,direction]
	if strings.Contains(s, ",") {
		parts := splitCSV(s)
		if len(parts) < 2 {
			return Entry{}, fmt.Errorf("csv line needs type,value")
		}
		return Entry{Type: parts[0], Value: parts[1], Direction: first(parts, 2)}, nil
	}
	// Bare token — classify.
	typ, err := classify(s)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Type: typ, Value: s, Direction: "egress"}, nil
}

func splitCSV(s string) []string {
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, strings.TrimSpace(strings.Trim(p, `"'`)))
	}
	return out
}

func classify(s string) (string, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Is4() || addr.Is6() {
			return "ip", nil
		}
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		_ = pfx
		return "cidr", nil
	}
	if looksDNS(s) {
		return "dns", nil
	}
	if looksSNI(s) {
		return "sni", nil
	}
	return "", fmt.Errorf("could not classify %q (want ip, cidr, dns name, or sni host)", s)
}

func looksDNS(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if strings.Contains(s, "://") || strings.ContainsAny(s, " /\\") {
		return false
	}
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func looksSNI(s string) bool {
	return looksDNS(s)
}

func normalize(in []Entry) Preview {
	var out Preview
	seen := map[string]bool{}
	for i, e := range in {
		e.Type = strings.ToLower(strings.TrimSpace(e.Type))
		e.Value = strings.TrimSpace(e.Value)
		e.Direction = strings.ToLower(strings.TrimSpace(e.Direction))
		if e.Direction == "" {
			e.Direction = "egress"
		}
		if e.Type == "ipv4" || e.Type == "ipv6" || e.Type == "addr" {
			e.Type = "ip"
		}
		if e.Type == "domain" || e.Type == "fqdn" {
			e.Type = "dns"
		}
		if e.Type != "ip" && e.Type != "cidr" && e.Type != "dns" && e.Type != "sni" {
			out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "type must be ip, cidr, dns, or sni"})
			continue
		}
		if e.Value == "" {
			out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "value is empty"})
			continue
		}
		if e.Direction != "egress" && e.Direction != "ingress" && e.Direction != "both" {
			out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "direction must be egress, ingress, or both"})
			continue
		}
		if e.Type == "ip" {
			if addr, err := netip.ParseAddr(e.Value); err != nil || addr.Zone() != "" {
				out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "invalid IP"})
				continue
			}
		}
		if e.Type == "cidr" {
			if _, err := netip.ParsePrefix(e.Value); err != nil {
				out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "invalid CIDR"})
				continue
			}
		}
		switch e.Type {
		case "ip":
			addr, _ := netip.ParseAddr(e.Value)
			e.Value = addr.Unmap().String()
		case "cidr":
			pfx, _ := netip.ParsePrefix(e.Value)
			e.Value = pfx.Masked().String()
		case "dns", "sni":
			if !looksDNS(e.Value) {
				out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "invalid hostname"})
				continue
			}
			e.Value = strings.ToLower(strings.TrimSuffix(e.Value, "."))
		}
		key := e.Type + "|" + e.Value + "|" + e.Direction
		if seen[key] {
			out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "duplicate"})
			continue
		}
		seen[key] = true
		if len(out.Entries) >= MaxEntries {
			out.Skipped = append(out.Skipped, Issue{Line: i + 1, Message: "capped at 1000 entries"})
			continue
		}
		out.Entries = append(out.Entries, e)
	}
	out.Count = len(out.Entries)
	out.Dropped = len(out.Skipped)
	return out
}

func first(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return ""
}
