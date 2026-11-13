// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// RuleDraft is a preview of an emergency eBPF rule parsed from natural
// language. It is never applied by this package.
type RuleDraft struct {
	Understood  bool           `json:"understood"`
	Confidence  string         `json:"confidence"` // high | medium | low
	Kind        string         `json:"kind,omitempty"`
	Summary     string         `json:"summary"`
	ApplyPath   string         `json:"applyPath,omitempty"`
	ApplyMethod string         `json:"applyMethod,omitempty"`
	Body        map[string]any `json:"body,omitempty"`
	CLI         string         `json:"cli,omitempty"`
	Warnings    []string       `json:"warnings"`
	Note        string         `json:"note"`
	// BlastRadius is an optional observe-only counterfactual from
	// deny-preview (attached by the API layer). Never applies a rule.
	BlastRadius map[string]any `json:"blastRadius,omitempty"`
}

var (
	reIPv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reCIDR   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)
	reCIDR6  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/\d{1,3}\b`)
	reIPv6   = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
	rePort   = regexp.MustCompile(`(?i)\bport\s+(\d{1,5})\b`)
	rePPS    = regexp.MustCompile(`(?i)\b(\d{1,9})\s*(?:pps|pkt/s|packets?/s(?:ec)?)\b`)
	reUID    = regexp.MustCompile(`(?i)\buid\s+(\d{1,10})\b`)
	reDNS    = regexp.MustCompile(`(?i)\b(?:dns|domain|name)\s+([a-z0-9._*-]+\.[a-z]{2,})\b`)
	reSNI    = regexp.MustCompile(`(?i)\b(?:sni|tls(?:\s+sni)?)\s+([a-z0-9._*-]+\.[a-z]{2,})\b`)
	reProc   = regexp.MustCompile(`(?i)\b(?:process|comm|binary)\s+([a-z0-9._-]{1,16})\b`)
	reBareFQ = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b`)
)

// DraftRule parses an operator sentence into a preview deny/rate rule.
// Returns Understood=false rather than guessing a destructive default.
func DraftRule(question string) RuleDraft {
	q := strings.TrimSpace(question)
	out := RuleDraft{
		Note: "Preview only. Netra will not apply this. Use netractl / the Firewall page / a mutating MCP tool after a human reviews the lease.",
		Warnings: []string{
			"Emergency rules are observe-first until an enforce lease is active.",
			"Prefer the narrowest match that still covers the incident.",
		},
	}
	if q == "" {
		out.Summary = "No question to draft from."
		return out
	}
	ql := strings.ToLower(q)
	if !containsAny(ql, "deny", "block", "drop", "rate", "limit", "throttle", "ban", "forbid", "allow", "except", "whitelist", "exception", "category", "conn-rate", "lateral", "exfil") {
		out.Summary = "That does not look like a deny/rate/allow request. Ask a diagnostic question instead, or say “deny …” / “allow …” / “rate-limit …”."
		return out
	}

	// Category deny → point at review-only drafts API.
	if containsAny(ql, "category", "social", "saas category") && containsAny(ql, "deny", "block", "draft") {
		out.Understood = true
		out.Confidence = "medium"
		out.Kind = "category-deny"
		out.ApplyMethod = "GET"
		out.ApplyPath = "/api/v1/insights/category-deny"
		out.Body = map[string]any{"reviewOnly": true}
		out.CLI = "netractl insights category-deny"
		out.Summary = "Category deny drafts (review-only) — pick hosts then apply leased SNI deny"
		out.Warnings = append(out.Warnings, "This returns drafts only; apply each SNI/DNS deny under an enforce lease after review.")
		return out
	}
	if containsAny(ql, "lateral", "port scan", "fan-out", "fan out") {
		out.Understood = true
		out.Confidence = "medium"
		out.Kind = "lateral-playbook"
		out.ApplyMethod = "GET"
		out.ApplyPath = "/api/v1/insights/lateral"
		out.CLI = "netractl insights lateral"
		out.Summary = "Lateral-movement playbooks from scan findings (review-only lease drafts)"
		return out
	}
	if containsAny(ql, "exfil", "data exfil", "fanout") {
		out.Understood = true
		out.Confidence = "medium"
		out.Kind = "exfil"
		out.ApplyMethod = "GET"
		out.ApplyPath = "/api/v1/insights/exfil"
		out.CLI = "netractl insights exfil"
		out.Summary = "Exfil fan-out / volume heuristics board (observe-only)"
		return out
	}

	dir := "egress"
	if strings.Contains(ql, "ingress") {
		dir = "ingress"
	} else if strings.Contains(ql, "both") {
		dir = "both"
	}

	if m := reCIDR.FindString(q); m != "" {
		if p, err := netip.ParsePrefix(m); err == nil {
			if containsAny(ql, "allow", "except", "whitelist", "exception") && !containsAny(ql, "deny", "block") {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "cidr-allow"
				out.ApplyMethod = "POST"
				out.ApplyPath = "/api/v1/ebpf/allow-cidr"
				out.Body = map[string]any{"cidr": p.String(), "direction": dir}
				out.CLI = "netractl ebpf allow-cidr add " + p.String() + " " + dir
				out.Summary = "CIDR allow-exception " + p.String() + " (" + dir + ")"
				out.Warnings = append(out.Warnings, "Allow is evaluated before deny/CIDR/port/rate. It does not itself enable enforce mode.")
				return out
			}
			out.Understood = true
			out.Confidence = "high"
			out.Kind = "cidr"
			out.ApplyMethod = "POST"
			out.ApplyPath = "/api/v1/ebpf/cidr"
			out.Body = map[string]any{"cidr": p.String(), "direction": dir}
			out.CLI = "netractl ebpf cidr add " + p.String() + " " + dir
			out.Summary = "CIDR deny " + p.String() + " (" + dir + ")"
			return out
		}
	}
	if m := reCIDR6.FindString(q); m != "" {
		if p, err := netip.ParsePrefix(m); err == nil {
			if containsAny(ql, "allow", "except", "whitelist", "exception") && !containsAny(ql, "deny", "block") {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "cidr-allow"
				out.ApplyMethod = "POST"
				out.ApplyPath = "/api/v1/ebpf/allow-cidr"
				out.Body = map[string]any{"cidr": p.String(), "direction": dir}
				out.CLI = "netractl ebpf allow-cidr add " + p.String() + " " + dir
				out.Summary = "CIDR allow-exception " + p.String() + " (" + dir + ")"
				out.Warnings = append(out.Warnings, "Allow is evaluated before deny/CIDR/port/rate. It does not itself enable enforce mode.")
				return out
			}
			out.Understood = true
			out.Confidence = "high"
			out.Kind = "cidr"
			out.ApplyMethod = "POST"
			out.ApplyPath = "/api/v1/ebpf/cidr"
			out.Body = map[string]any{"cidr": p.String(), "direction": dir}
			out.CLI = "netractl ebpf cidr add " + p.String() + " " + dir
			out.Summary = "CIDR deny " + p.String() + " (" + dir + ")"
			return out
		}
	}

	if m := reIPv4.FindString(q); m != "" {
		if addr, err := netip.ParseAddr(m); err == nil && addr.Is4() {
			if containsAny(ql, "allow", "except", "whitelist", "exception") && !containsAny(ql, "deny", "block") {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "allow"
				out.ApplyMethod = "POST"
				out.ApplyPath = "/api/v1/ebpf/allow"
				out.Body = map[string]any{"ip": addr.String()}
				out.CLI = "netractl ebpf allow add " + addr.String()
				out.Summary = "Exact IP allow-exception " + addr.String()
				out.Warnings = append(out.Warnings, "Allow is evaluated before deny/rate. It does not itself enable enforce mode.")
				return out
			}
			if pps := parsePPS(ql); pps > 0 {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "rate"
				out.ApplyMethod = "PUT"
				out.ApplyPath = "/api/v1/ebpf/rate"
				out.Body = map[string]any{"destination": addr.String(), "pps": pps}
				out.CLI = "netractl ebpf rate set " + addr.String() + " " + strconv.FormatUint(uint64(pps), 10)
				out.Summary = "IPv4 destination PPS ceiling " + addr.String() + " @ " + strconv.FormatUint(uint64(pps), 10)
				return out
			}
			out.Understood = true
			out.Confidence = "high"
			out.Kind = "ip"
			out.ApplyMethod = "POST"
			out.ApplyPath = "/api/v1/ebpf/deny"
			out.Body = map[string]any{"ip": addr.String()}
			out.CLI = "netractl ebpf deny add " + addr.String()
			out.Summary = "Exact IP deny " + addr.String()
			return out
		}
	}

	if m := reIPv6.FindString(q); m != "" {
		if addr, err := netip.ParseAddr(m); err == nil && addr.Is6() {
			if containsAny(ql, "allow", "except", "whitelist", "exception") && !containsAny(ql, "deny", "block") {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "allow"
				out.ApplyMethod = "POST"
				out.ApplyPath = "/api/v1/ebpf/allow"
				out.Body = map[string]any{"ip": addr.String()}
				out.CLI = "netractl ebpf allow add " + addr.String()
				out.Summary = "Exact IP allow-exception " + addr.String()
				out.Warnings = append(out.Warnings, "Allow is evaluated before deny/rate. It does not itself enable enforce mode.")
				return out
			}
			if pps := parsePPS(ql); pps > 0 {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "rate"
				out.ApplyMethod = "PUT"
				out.ApplyPath = "/api/v1/ebpf/rate"
				out.Body = map[string]any{"destination": addr.String(), "pps": pps}
				out.CLI = "netractl ebpf rate set " + addr.String() + " " + strconv.FormatUint(uint64(pps), 10)
				out.Summary = "IPv6 destination PPS ceiling " + addr.String() + " @ " + strconv.FormatUint(uint64(pps), 10)
				return out
			}
			out.Understood = true
			out.Confidence = "high"
			out.Kind = "ip"
			out.ApplyMethod = "POST"
			out.ApplyPath = "/api/v1/ebpf/deny"
			out.Body = map[string]any{"ip": addr.String()}
			out.CLI = "netractl ebpf deny add " + addr.String()
			out.Summary = "Exact IP deny " + addr.String()
			return out
		}
	}

	if m := rePort.FindStringSubmatch(q); len(m) == 2 {
		port, err := strconv.ParseUint(m[1], 10, 16)
		if err == nil && port > 0 {
			proto := "ANY"
			if strings.Contains(ql, "udp") {
				proto = "UDP"
			} else if strings.Contains(ql, "tcp") {
				proto = "TCP"
			}
			if containsAny(ql, "allow", "except", "whitelist", "exception") && !containsAny(ql, "deny", "block") {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "port-allow"
				out.ApplyMethod = "POST"
				out.ApplyPath = "/api/v1/ebpf/allow-port"
				out.Body = map[string]any{"protocol": proto, "port": uint16(port), "direction": dir}
				out.CLI = "netractl ebpf allow-port add " + proto + " " + m[1] + " " + dir
				out.Summary = proto + "/" + m[1] + " allow-exception (" + dir + ")"
				out.Warnings = append(out.Warnings, "Allow is evaluated before deny/CIDR/port/rate. It does not itself enable enforce mode.")
				if proto == "ANY" {
					out.Warnings = append(out.Warnings, "Protocol was not named; drafted as ANY.")
					out.Confidence = "medium"
				}
				return out
			}
			out.Understood = true
			out.Confidence = "high"
			out.Kind = "port"
			out.ApplyMethod = "POST"
			out.ApplyPath = "/api/v1/ebpf/port"
			out.Body = map[string]any{"protocol": proto, "port": uint16(port), "direction": dir}
			out.CLI = "netractl ebpf port add " + proto + " " + m[1] + " " + dir
			out.Summary = proto + "/" + m[1] + " deny (" + dir + ")"
			if proto == "ANY" {
				out.Warnings = append(out.Warnings, "Protocol was not named; drafted as ANY.")
				out.Confidence = "medium"
			}
			return out
		}
	}

	if m := reSNI.FindStringSubmatch(q); len(m) == 2 {
		return dnsLikeDraft(&out, "sni", m[1], "/api/v1/ebpf/sni", "netractl ebpf sni add ")
	}
	if m := reDNS.FindStringSubmatch(q); len(m) == 2 {
		return dnsLikeDraft(&out, "dns", m[1], "/api/v1/ebpf/dns", "netractl ebpf dns add ")
	}

	if m := reUID.FindStringSubmatch(q); len(m) == 2 {
		uid, err := strconv.ParseUint(m[1], 10, 32)
		if err == nil {
			if containsAny(ql, "allow", "except", "whitelist", "exception") && !containsAny(ql, "deny", "block") {
				out.Understood = true
				out.Confidence = "high"
				out.Kind = "uid-allow"
				out.ApplyMethod = "POST"
				out.ApplyPath = "/api/v1/ebpf/allow-uid"
				out.Body = map[string]any{"uid": uint32(uid)}
				out.CLI = "netractl ebpf allow-uid add " + m[1]
				out.Summary = "UID allow-exception " + m[1] + " on new sockets"
				out.Warnings = append(out.Warnings, "Allow is evaluated before UID/comm deny at the socket hook. It does not itself enable enforce mode.")
				if uid == 0 {
					out.Warnings = append(out.Warnings, "UID 0 is root — confirm this is the intended blast radius.")
					out.Confidence = "medium"
				}
				return out
			}
			out.Understood = true
			out.Confidence = "high"
			out.Kind = "uid"
			out.ApplyMethod = "POST"
			out.ApplyPath = "/api/v1/ebpf/uid"
			out.Body = map[string]any{"uid": uint32(uid)}
			out.CLI = "netractl ebpf uid add " + m[1]
			out.Summary = "UID deny " + m[1] + " on new sockets"
			if uid == 0 {
				out.Warnings = append(out.Warnings, "UID 0 is root — confirm this is the intended blast radius.")
				out.Confidence = "medium"
			}
			return out
		}
	}

	if m := reProc.FindStringSubmatch(q); len(m) == 2 {
		comm := m[1]
		if containsAny(ql, "allow", "except", "whitelist", "exception") && !containsAny(ql, "deny", "block") {
			out.Understood = true
			out.Confidence = "medium"
			out.Kind = "process-allow"
			out.ApplyMethod = "POST"
			out.ApplyPath = "/api/v1/ebpf/allow-process"
			out.Body = map[string]any{"name": comm}
			out.CLI = "netractl ebpf allow-process add " + comm
			out.Summary = "Process comm allow-exception " + comm
			out.Warnings = append(out.Warnings, "comm is a 16-byte kernel name, not a full path.", "Allow is evaluated before UID/comm deny at the socket hook. It does not itself enable enforce mode.")
			return out
		}
		out.Understood = true
		out.Confidence = "medium"
		out.Kind = "process"
		out.ApplyMethod = "POST"
		out.ApplyPath = "/api/v1/ebpf/process"
		out.Body = map[string]any{"name": comm}
		out.CLI = "netractl ebpf process add " + comm
		out.Summary = "Process comm deny " + comm
		out.Warnings = append(out.Warnings, "comm is a 16-byte kernel name, not a full path.")
		return out
	}

	if containsAny(ql, "sni", "tls") {
		if m := reBareFQ.FindStringSubmatch(q); len(m) == 2 && !looksLikeSentenceWord(m[1]) {
			return dnsLikeDraft(&out, "sni", m[1], "/api/v1/ebpf/sni", "netractl ebpf sni add ")
		}
	}
	if containsAny(ql, "dns", "domain") {
		if m := reBareFQ.FindStringSubmatch(q); len(m) == 2 && !looksLikeSentenceWord(m[1]) {
			return dnsLikeDraft(&out, "dns", m[1], "/api/v1/ebpf/dns", "netractl ebpf dns add ")
		}
	}

	out.Summary = "Heard a deny/rate intent but could not extract a safe exact match (IP, CIDR, port, DNS, SNI, UID, or process comm)."
	out.Confidence = "low"
	return out
}

func dnsLikeDraft(out *RuleDraft, kind, name, path, cliPrefix string) RuleDraft {
	name = strings.ToLower(strings.Trim(name, "."))
	out.Understood = true
	out.Confidence = "high"
	out.Kind = kind
	out.ApplyMethod = "POST"
	out.ApplyPath = path
	out.Body = map[string]any{"name": name}
	out.CLI = cliPrefix + name
	if kind == "sni" {
		out.Summary = "TLS SNI deny " + name
		out.Warnings = append(out.Warnings, "SNI deny only fires when ClientHello SNI is parsed from the current egress skb.")
	} else {
		out.Summary = "Cleartext DNS-name deny " + name
		out.Warnings = append(out.Warnings, "DNS-name deny matches cleartext UDP/53 query names only.")
	}
	return *out
}

func parsePPS(ql string) uint32 {
	m := rePPS.FindStringSubmatch(ql)
	if len(m) != 2 {
		return 0
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || n == 0 {
		return 0
	}
	return uint32(n)
}

func looksLikeSentenceWord(s string) bool {
	switch strings.ToLower(s) {
	case "example.com", "foo.com":
		return false
	}
	return !strings.Contains(s, ".")
}
