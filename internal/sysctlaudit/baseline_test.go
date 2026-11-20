// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysctlaudit

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestClassifyKnownBadValues(t *testing.T) {
	cases := []struct {
		entry models.SysctlAuditEntry
		want  string
	}{
		{models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "0"}, SeverityCritical},
		{models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "1"}, SeverityInfo},
		{models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.accept_redirects", Interface: "eth0", Category: CategorySecurity, Value: "1"}, SeverityCritical},
		{models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.accept_source_route", Interface: "eth0", Category: CategorySecurity, Value: "1"}, SeverityCritical},
		{models.SysctlAuditEntry{Name: "net.ipv4.tcp_syncookies", Category: CategorySecurity, Value: "0"}, SeverityCritical},
		{models.SysctlAuditEntry{Name: "net.ipv4.tcp_syncookies", Category: CategorySecurity, Value: "1"}, SeverityInfo},
		{models.SysctlAuditEntry{Name: "net.ipv4.tcp_sack", Category: CategoryTCP, Value: "0"}, SeverityWarning},
		{models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.proxy_arp", Interface: "eth0", Category: CategorySecurity, Value: "1"}, SeverityWarning},
	}
	for _, c := range cases {
		got := Classify(c.entry)
		if got.Severity != c.want {
			t.Errorf("Classify(%s=%s): severity=%s, want %s", c.entry.Name, c.entry.Value, got.Severity, c.want)
		}
	}
}

// TestContextDependentSysctlsStayInformational locks in the deliberate
// scope boundary: these sysctls have no universal "correct" value and must
// never gain a false pass/fail verdict by accident.
func TestContextDependentSysctlsStayInformational(t *testing.T) {
	contextDependent := []models.SysctlAuditEntry{
		{Name: "net.ipv4.ip_forward", Category: CategorySecurity, Value: "1"},
		{Name: "net.ipv6.conf.eth0.disable_ipv6", Interface: "eth0", Category: CategoryIPv6, Value: "1"},
		{Name: "net.ipv6.conf.eth0.accept_ra", Interface: "eth0", Category: CategoryIPv6, Value: "1"},
		{Name: "net.ipv6.conf.eth0.accept_ra_defrtr", Interface: "eth0", Category: CategoryIPv6, Value: "1"},
		{Name: "net.ipv6.conf.eth0.use_tempaddr", Interface: "eth0", Category: CategoryIPv6, Value: "2"},
		{Name: "net.ipv6.conf.eth0.autoconf", Interface: "eth0", Category: CategoryIPv6, Value: "0"},
		{Name: "net.ipv4.tcp_congestion_control", Category: CategoryTCP, Value: "bbr"},
		{Name: "net.ipv4.tcp_fastopen", Category: CategoryTCP, Value: "3"},
		{Name: "net.ipv4.tcp_ecn", Category: CategoryTCP, Value: "2"},
		{Name: "net.ipv4.tcp_fin_timeout", Category: CategoryTCP, Value: "60"},
		{Name: "net.ipv4.tcp_keepalive_time", Category: CategoryTCP, Value: "7200"},
		{Name: "net.ipv4.tcp_keepalive_intvl", Category: CategoryTCP, Value: "75"},
		{Name: "net.ipv4.tcp_keepalive_probes", Category: CategoryTCP, Value: "9"},
		{Name: "net.ipv4.tcp_tw_reuse", Category: CategoryTCP, Value: "0"},
		{Name: "net.ipv4.tcp_slow_start_after_idle", Category: CategoryTCP, Value: "1"},
		{Name: "net.ipv4.tcp_mtu_probing", Category: CategoryTCP, Value: "0"},
		{Name: "net.netfilter.nf_conntrack_tcp_timeout_established", Category: CategoryConntrack, Value: "432000"},
		{Name: "net.netfilter.nf_conntrack_tcp_timeout_time_wait", Category: CategoryConntrack, Value: "120"},
		{Name: "net.netfilter.nf_conntrack_tcp_timeout_close_wait", Category: CategoryConntrack, Value: "60"},
		{Name: "net.netfilter.nf_conntrack_udp_timeout", Category: CategoryConntrack, Value: "30"},
		{Name: "net.netfilter.nf_conntrack_udp_timeout_stream", Category: CategoryConntrack, Value: "180"},
		{Name: "net.netfilter.nf_conntrack_generic_timeout", Category: CategoryConntrack, Value: "600"},
		{Name: "net.bridge.bridge-nf-call-iptables", Category: CategoryARPBridge, Value: "1"},
		{Name: "net.bridge.bridge-nf-call-ip6tables", Category: CategoryARPBridge, Value: "1"},
		{Name: "net.ipv4.conf.eth0.arp_filter", Interface: "eth0", Category: CategoryARPBridge, Value: "0"},
		{Name: "net.ipv4.conf.eth0.arp_ignore", Interface: "eth0", Category: CategoryARPBridge, Value: "0"},
		{Name: "net.ipv4.conf.eth0.arp_announce", Interface: "eth0", Category: CategoryARPBridge, Value: "0"},
		{Name: "net.ipv4.neigh.default.gc_thresh1", Category: CategoryARPBridge, Value: "128"},
	}
	for _, e := range contextDependent {
		got := Classify(e)
		if got.Severity != SeverityInfo {
			t.Errorf("Classify(%s): severity=%s, want %s (context-dependent, no universal baseline)", e.Name, got.Severity, SeverityInfo)
		}
	}
}

func TestClassifyUnknownSysctlIsInformational(t *testing.T) {
	got := Classify(models.SysctlAuditEntry{Name: "net.ipv4.some_future_sysctl", Category: CategorySecurity, Value: "42"})
	if got.Severity != SeverityInfo || !got.Informational {
		t.Fatalf("expected unknown sysctl to be informational, got %#v", got)
	}
}
