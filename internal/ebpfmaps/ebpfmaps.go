// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package ebpfmaps builds a read-only, operator-friendly view of Netra
// datapath map contents from the controller desired state (the same
// entries agents reconcile into /sys/fs/bpf/netra). This is not a raw
// bpftool dump — it is the control-plane inventory operators need to
// answer "what is in the maps right now?"
package ebpfmaps

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Limits mirror bpf/netra_tc.c max_entries (compile-time constants).
var Limits = map[string]int{
	"blocked_v4":         4096,
	"blocked_v6":         4096,
	"blocked_ingress_v4": 4096,
	"blocked_ingress_v6": 4096,
	"blocked_cidr":       8192,
	"blocked_ports":      4096,
	"blocked_uids":       4096,
	"blocked_dns":        4096,
	"blocked_sni":        4096,
	"blocked_comms":      4096,
	"allowed_v4":         4096,
	"allowed_v6":         4096,
	"allowed_cidr":       8192,
	"allowed_ports":      4096,
	"allowed_uids":       4096,
	"allowed_comms":      4096,
	"rate":               4096,
	"conn_rate_limits":   4096,
	"syndrop":            4096,
	"syndrop_cidr":       8192,
	"capgate":            2,
	"netpol_deny":        65536,
	"netpol_rules":       65536,
	"netpol_default":     16384,
}

// Report is the JSON shape for GET /api/v1/ebpf/maps.
type Report struct {
	GeneratedAt  time.Time `json:"generatedAt"`
	Mode         string    `json:"mode"`
	Revision     uint64    `json:"revision"`
	PinRoot      string    `json:"pinRoot"`
	Note         string    `json:"note"`
	FilledMaps   int       `json:"filledMaps"`
	EmptyMaps    int       `json:"emptyMaps"`
	TotalEntries int       `json:"totalEntries"`
	Maps         []MapView `json:"maps"`
}

// MapView is one logical map family with human-readable entries.
type MapView struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Group   string   `json:"group"` // deny | allow | rate | syn-drop | policy | capability | scope
	BPFMap  string   `json:"bpfMap"`
	Count   int      `json:"count"`
	Limit   int      `json:"limit"`
	Entries []string `json:"entries"`
}

const maxEntries = 200

// Build converts controller config into a map inventory.
func Build(cfg models.EBPFFastPathConfig, now time.Time) Report {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maps := []MapView{
		strMap("blocked_v4", "Deny IPv4 (egress)", "deny", "blocked_v4", cfg.BlockedIPv4),
		strMap("blocked_v6", "Deny IPv6 (egress)", "deny", "blocked_v6", cfg.BlockedIPv6),
		strMap("blocked_ingress_v4", "Deny IPv4 (ingress)", "deny", "blocked_ingress_v4", cfg.BlockedIngressIPv4),
		strMap("blocked_ingress_v6", "Deny IPv6 (ingress)", "deny", "blocked_ingress_v6", cfg.BlockedIngressIPv6),
		cidrMap("blocked_cidr", "Deny CIDR", "deny", "blocked_cidr_v4/v6", cfg.BlockedCIDRs),
		portMap("blocked_ports", "Deny port", "deny", "blocked_ports", cfg.BlockedPorts),
		uidMap("blocked_uids", "Deny UID", "deny", "blocked_uids", cfg.BlockedUIDs),
		strMap("blocked_dns", "Deny DNS name", "deny", "blocked_dns", cfg.BlockedDNS),
		strMap("blocked_sni", "Deny TLS SNI", "deny", "blocked_sni", cfg.BlockedSNI),
		strMap("blocked_comms", "Deny process (comm)", "deny", "blocked_comms", cfg.BlockedProcesses),
		strMap("allowed_v4", "Allow IPv4 exception", "allow", "allowed_v4", cfg.AllowedIPv4),
		strMap("allowed_v6", "Allow IPv6 exception", "allow", "allowed_v6", cfg.AllowedIPv6),
		cidrMap("allowed_cidr", "Allow CIDR exception", "allow", "allowed_cidr_v4/v6", cfg.AllowedCIDRs),
		portMap("allowed_ports", "Allow port exception", "allow", "allowed_ports", cfg.AllowedPorts),
		uidMap("allowed_uids", "Allow UID exception", "allow", "allowed_uids", cfg.AllowedUIDs),
		strMap("allowed_comms", "Allow process exception", "allow", "allowed_comms", cfg.AllowedProcesses),
		rateMap(cfg.RateLimits),
		connRateMap(cfg.ConnRateLimits),
		synDropMap(cfg.SynDrop),
		synDropCIDRMap(cfg.SynDropCIDR),
		strMap("capgate", "Capability-gated deny", "capability", "capgate_pids (via deniedCapabilities)", cfg.DeniedCapabilities),
		strMap("exehash", "Exe-hash leased deny", "exehash", "exehash_pids (via blockedExeHashes)", cfg.BlockedExeHashes),
		netpolDenyMap(cfg.NetPolDenies),
		netpolRulesMap(cfg.NetPolRules),
		netpolDefaultMap(cfg.NetPolDefaultDenies),
		scopeMap(cfg),
	}

	rep := Report{
		GeneratedAt: now.UTC(),
		Mode:        cfg.Mode,
		Revision:    cfg.Revision,
		PinRoot:     "/sys/fs/bpf/netra",
		Note:        "Controller desired map contents pushed to agents under /sys/fs/bpf/netra. Not a raw bpftool dump of kernel map memory.",
		Maps:        maps,
	}
	for _, m := range maps {
		rep.TotalEntries += m.Count
		if m.Count > 0 {
			rep.FilledMaps++
		} else {
			rep.EmptyMaps++
		}
	}
	return rep
}

// Format writes a human-readable board to w.
func Format(w io.Writer, rep Report) {
	fmt.Fprintf(w, "Netra datapath maps (controller view)\n")
	fmt.Fprintf(w, "Mode %s · revision %d · pin %s\n", orDash(rep.Mode), rep.Revision, rep.PinRoot)
	fmt.Fprintf(w, "%s\n\n", rep.Note)
	fmt.Fprintf(w, "%d filled · %d empty · %d total entries\n\n", rep.FilledMaps, rep.EmptyMaps, rep.TotalEntries)

	groups := []string{"deny", "allow", "rate", "syn-drop", "capability", "policy", "scope"}
	titles := map[string]string{
		"deny": "DENY", "allow": "ALLOW", "rate": "RATE LIMITS",
		"syn-drop": "SYN-DROP FLAGS", "capability": "CAPABILITY GATE",
		"policy": "NETWORK POLICY", "scope": "SCOPE",
	}
	byGroup := map[string][]MapView{}
	for _, m := range rep.Maps {
		byGroup[m.Group] = append(byGroup[m.Group], m)
	}

	var empty []string
	for _, g := range groups {
		maps := byGroup[g]
		filled := 0
		for _, m := range maps {
			if m.Count > 0 {
				filled++
			} else {
				empty = append(empty, m.BPFMap)
			}
		}
		if filled == 0 {
			continue
		}
		fmt.Fprintf(w, "%s\n", titles[g])
		for _, m := range maps {
			if m.Count == 0 {
				continue
			}
			lim := ""
			if m.Limit > 0 {
				lim = fmt.Sprintf("  %d/%d", m.Count, m.Limit)
			} else {
				lim = fmt.Sprintf("  %d", m.Count)
			}
			fmt.Fprintf(w, "  %-28s [%s]%s\n", m.Title, m.BPFMap, lim)
			for _, e := range m.Entries {
				fmt.Fprintf(w, "    · %s\n", e)
			}
			if m.Count > len(m.Entries) {
				fmt.Fprintf(w, "    · … and %d more\n", m.Count-len(m.Entries))
			}
		}
		fmt.Fprintln(w)
	}

	if len(empty) > 0 {
		sort.Strings(empty)
		fmt.Fprintf(w, "Empty maps (%d): %s\n", len(empty), strings.Join(empty, ", "))
	}
}

func strMap(id, title, group, bpf string, values []string) MapView {
	entries := make([]string, 0, len(values))
	entries = append(entries, values...)
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: id, Title: title, Group: group, BPFMap: bpf, Count: len(values), Limit: Limits[id], Entries: entries}
}

func uidMap(id, title, group, bpf string, values []uint32) MapView {
	entries := make([]string, 0, len(values))
	for _, u := range values {
		entries = append(entries, fmt.Sprintf("uid %d", u))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: id, Title: title, Group: group, BPFMap: bpf, Count: len(values), Limit: Limits[id], Entries: entries}
}

func cidrMap(id, title, group, bpf string, rules []models.EBPFCIDRRule) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		dir := r.Direction
		if dir == "" {
			dir = "egress"
		}
		entries = append(entries, fmt.Sprintf("%s (%s)", r.CIDR, dir))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: id, Title: title, Group: group, BPFMap: bpf, Count: len(rules), Limit: Limits[id], Entries: entries}
}

func portMap(id, title, group, bpf string, rules []models.EBPFPortRule) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		proto := r.Protocol
		if proto == "" {
			proto = "ANY"
		}
		dir := r.Direction
		if dir == "" {
			dir = "egress"
		}
		entries = append(entries, fmt.Sprintf("%s/%d (%s)", proto, r.Port, dir))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: id, Title: title, Group: group, BPFMap: bpf, Count: len(rules), Limit: Limits[id], Entries: entries}
}

func rateMap(rules []models.EBPFRateLimit) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		parts := []string{r.Destination}
		if r.PPS > 0 {
			parts = append(parts, fmt.Sprintf("pps=%d", r.PPS))
		}
		if r.BPS > 0 {
			parts = append(parts, fmt.Sprintf("bps=%d", r.BPS))
		}
		entries = append(entries, strings.Join(parts, " "))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: "rate", Title: "Destination rate limit", Group: "rate", BPFMap: "rate_v4/v6", Count: len(rules), Limit: Limits["rate"], Entries: entries}
}

func connRateMap(rules []models.EBPFConnRateLimit) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, fmt.Sprintf("%s  %s  per-second=%d", r.ID, scopeLabel(r.Selector), r.PerSecond))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: "conn_rate_limits", Title: "Workload connect-rate limit", Group: "rate", BPFMap: "conn_rate_limits", Count: len(rules), Limit: Limits["conn_rate_limits"], Entries: entries}
}

func synDropMap(rules []models.EBPFSynDropEntry) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, fmt.Sprintf("%s (%s)", r.Address, r.Direction))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: "syndrop", Title: "SYN-drop exact IP", Group: "syn-drop", BPFMap: "syndrop_v4/v6", Count: len(rules), Limit: Limits["syndrop"], Entries: entries}
}

func synDropCIDRMap(rules []models.EBPFSynDropCIDR) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, fmt.Sprintf("%s (%s)", r.CIDR, r.Direction))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: "syndrop_cidr", Title: "SYN-drop CIDR", Group: "syn-drop", BPFMap: "syndrop_cidr_v4/v6", Count: len(rules), Limit: Limits["syndrop_cidr"], Entries: entries}
}

func netpolDenyMap(rules []models.NetPolPeerDeny) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		port := "any"
		if r.Port > 0 {
			port = fmt.Sprintf("%d", r.Port)
		}
		entries = append(entries, fmt.Sprintf("cgroup=%d peer=%s port=%s proto=%s dir=%s", r.CgroupID, r.PeerIPv4, port, orDash(r.Protocol), orDash(r.Direction)))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: "netpol_deny", Title: "NetPol peer deny (v1)", Group: "policy", BPFMap: "netpol_deny4", Count: len(rules), Limit: Limits["netpol_deny"], Entries: entries}
}

func netpolRulesMap(rules []models.NetPolRule) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		peer := r.PeerIPv4
		if peer == "" {
			peer = "*"
		}
		port := "any"
		if r.Port > 0 {
			port = fmt.Sprintf("%d", r.Port)
		}
		entries = append(entries, fmt.Sprintf("%s %s peer=%s port=%s proto=%s dir=%s", r.ID, r.Action, peer, port, orDash(r.Protocol), orDash(r.Direction)))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: "netpol_rules", Title: "NetPol rules (v2)", Group: "policy", BPFMap: "netpol_rules4", Count: len(rules), Limit: Limits["netpol_rules"], Entries: entries}
}

func netpolDefaultMap(rules []models.NetPolDefaultDeny) MapView {
	entries := make([]string, 0, len(rules))
	for _, r := range rules {
		until := "no-lease"
		if r.EnabledUntil != nil {
			until = "until " + r.EnabledUntil.UTC().Format(time.RFC3339)
		}
		entries = append(entries, fmt.Sprintf("%s  %s", scopeLabel(r.Selector), until))
	}
	sort.Strings(entries)
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return MapView{ID: "netpol_default", Title: "NetPol default-deny", Group: "policy", BPFMap: "netpol_default4", Count: len(rules), Limit: Limits["netpol_default"], Entries: entries}
}

func scopeMap(cfg models.EBPFFastPathConfig) MapView {
	mode := cfg.ScopeMode
	if mode == "" {
		mode = "all"
	}
	entries := []string{fmt.Sprintf("mode=%s", mode)}
	for _, s := range cfg.WorkloadScopes {
		entries = append(entries, scopeLabel(s))
	}
	return MapView{ID: "scope", Title: "Workload scope", Group: "scope", BPFMap: "scope_mode + enforced_cgroups", Count: len(cfg.WorkloadScopes), Limit: 0, Entries: entries}
}

func scopeLabel(s models.EBPFWorkloadScope) string {
	parts := []string{}
	if s.Namespace != "" {
		parts = append(parts, "ns="+s.Namespace)
	}
	if s.Pod != "" {
		parts = append(parts, "pod="+s.Pod)
	}
	if s.WorkloadKind != "" || s.WorkloadName != "" {
		parts = append(parts, fmt.Sprintf("%s/%s", s.WorkloadKind, s.WorkloadName))
	}
	if s.CgroupID != 0 {
		parts = append(parts, fmt.Sprintf("cgroup=%d", s.CgroupID))
	}
	if len(s.Labels) > 0 {
		keys := make([]string, 0, len(s.Labels))
		for k := range s.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+"="+s.Labels[k])
		}
	}
	if len(parts) == 0 {
		return "(empty selector)"
	}
	return strings.Join(parts, " ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
