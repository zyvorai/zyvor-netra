// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package sysctlaudit collects a read-only, flat inventory of network
// hardening and tuning sysctls and classifies them against an established
// baseline. Unlike internal/kerneldiag, this is not evidence-correlated to
// observed congestion/drops, and it never writes sysctls: findings are
// reported for operator review only.
package sysctlaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

const (
	CategorySecurity  = "security"
	CategoryIPv6      = "ipv6"
	CategoryTCP       = "tcp"
	CategoryConntrack = "conntrack"
	CategoryARPBridge = "arp-bridge"
)

// globalTunable is a non-per-interface sysctl, tagged with its category at
// collection time so the web UI and outlier logic never need to re-derive it.
type globalTunable struct {
	Name     string
	Category string
}

// GlobalTunables covers sysctls that have exactly one instance on the host
// (no per-interface conf.* variant). Missing files are normal across kernel
// versions/namespaces and are simply omitted.
var GlobalTunables = []globalTunable{
	{"net.ipv4.tcp_syncookies", CategorySecurity},
	{"net.ipv4.icmp_echo_ignore_broadcasts", CategorySecurity},
	{"net.ipv4.icmp_ignore_bogus_error_responses", CategorySecurity},
	{"net.ipv4.ip_forward", CategorySecurity},

	{"net.ipv4.tcp_fin_timeout", CategoryTCP},
	{"net.ipv4.tcp_keepalive_time", CategoryTCP},
	{"net.ipv4.tcp_keepalive_intvl", CategoryTCP},
	{"net.ipv4.tcp_keepalive_probes", CategoryTCP},
	{"net.ipv4.tcp_tw_reuse", CategoryTCP},
	{"net.ipv4.tcp_slow_start_after_idle", CategoryTCP},
	{"net.ipv4.tcp_mtu_probing", CategoryTCP},
	{"net.ipv4.tcp_sack", CategoryTCP},
	{"net.ipv4.tcp_timestamps", CategoryTCP},
	{"net.ipv4.tcp_window_scaling", CategoryTCP},
	{"net.ipv4.tcp_congestion_control", CategoryTCP},
	{"net.ipv4.tcp_fastopen", CategoryTCP},
	{"net.ipv4.tcp_ecn", CategoryTCP},

	{"net.netfilter.nf_conntrack_tcp_timeout_established", CategoryConntrack},
	{"net.netfilter.nf_conntrack_tcp_timeout_time_wait", CategoryConntrack},
	{"net.netfilter.nf_conntrack_tcp_timeout_close_wait", CategoryConntrack},
	{"net.netfilter.nf_conntrack_udp_timeout", CategoryConntrack},
	{"net.netfilter.nf_conntrack_udp_timeout_stream", CategoryConntrack},
	{"net.netfilter.nf_conntrack_generic_timeout", CategoryConntrack},

	{"net.bridge.bridge-nf-call-iptables", CategoryARPBridge},
	{"net.bridge.bridge-nf-call-ip6tables", CategoryARPBridge},
	{"net.ipv4.neigh.default.gc_thresh1", CategoryARPBridge},
	{"net.ipv4.neigh.default.gc_thresh2", CategoryARPBridge},
	{"net.ipv4.neigh.default.gc_thresh3", CategoryARPBridge},
}

// SecuritySuffixes are per-interface net.ipv4.conf.<if>.* hardening keys.
var SecuritySuffixes = []string{
	"rp_filter", "accept_redirects", "secure_redirects", "send_redirects",
	"accept_source_route", "log_martians", "proxy_arp",
}

// IPv6Suffixes are per-interface net.ipv6.conf.<if>.* posture keys.
var IPv6Suffixes = []string{
	"disable_ipv6", "accept_ra", "accept_ra_defrtr", "use_tempaddr", "autoconf",
}

// ARPSuffixes are per-interface net.ipv4.conf.<if>.* ARP keys.
var ARPSuffixes = []string{"arp_filter", "arp_ignore", "arp_announce"}

// Collect reads from root, which is "/" in production and a temporary fixture
// in tests. All errors are best-effort: a restricted container should still
// report the subset mounted into its namespace, and a sysctl absent on this
// kernel/namespace is simply omitted rather than treated as an error.
func Collect(root string) models.SysctlAuditSnapshot {
	if root == "" {
		root = "/"
	}
	out := models.SysctlAuditSnapshot{}
	for _, t := range GlobalTunables {
		if e, ok := readEntry(root, t.Name, "", t.Category); ok {
			out.Entries = append(out.Entries, e)
		}
	}
	for _, iface := range interfaces(root) {
		for _, suffix := range SecuritySuffixes {
			if e, ok := readInterfaceEntry(root, "ipv4", iface, suffix, CategorySecurity); ok {
				out.Entries = append(out.Entries, e)
			}
		}
		for _, suffix := range ARPSuffixes {
			if e, ok := readInterfaceEntry(root, "ipv4", iface, suffix, CategoryARPBridge); ok {
				out.Entries = append(out.Entries, e)
			}
		}
		for _, suffix := range IPv6Suffixes {
			if e, ok := readInterfaceEntry(root, "ipv6", iface, suffix, CategoryIPv6); ok {
				out.Entries = append(out.Entries, e)
			}
		}
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Name < out.Entries[j].Name })
	return out
}

// readEntry reads a global (non-per-interface) sysctl. name is a fixed
// constant this package controls (see GlobalTunables), so a naive
// dot-to-slash translation is safe.
func readEntry(root, name, iface, category string) (models.SysctlAuditEntry, bool) {
	rel := "proc/sys/" + strings.ReplaceAll(name, ".", "/")
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return models.SysctlAuditEntry{}, false
	}
	return models.SysctlAuditEntry{
		Name:      name,
		Interface: iface,
		Category:  category,
		Value:     strings.Join(strings.Fields(string(b)), " "),
		Source:    "/" + rel,
	}, true
}

// readInterfaceEntry reads a per-interface net.<family>.conf.<iface>.<suffix>
// sysctl. The filesystem path is built with iface as one opaque path
// segment (via filepath.Join), never by dot-splitting a joined string —
// VLAN sub-interface names like "eth0.100" contain a literal dot that is
// part of the interface name, not a sysctl-name separator, and Linux itself
// keeps it as one /proc/sys/net/*/conf/ directory entry.
func readInterfaceEntry(root, family, iface, suffix, category string) (models.SysctlAuditEntry, bool) {
	rel := filepath.Join("proc/sys/net", family, "conf", iface, suffix)
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return models.SysctlAuditEntry{}, false
	}
	return models.SysctlAuditEntry{
		Name:      fmt.Sprintf("net.%s.conf.%s.%s", family, iface, suffix),
		Interface: iface,
		Category:  category,
		Value:     strings.Join(strings.Fields(string(b)), " "),
		Source:    "/" + rel,
	}, true
}

// interfaces returns the union of interface (and "all"/"default" pseudo-
// entry) names found under the ipv4 and ipv6 conf directories. Reading both
// and unioning them means an IPv6-only or IPv4-only interface is still
// covered for whichever category applies to it.
func interfaces(root string) []string {
	seen := map[string]struct{}{}
	for _, dir := range []string{"proc/sys/net/ipv4/conf", "proc/sys/net/ipv6/conf"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				seen[e.Name()] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
