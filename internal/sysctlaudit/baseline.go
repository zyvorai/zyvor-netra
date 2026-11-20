// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysctlaudit

import (
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Rule classifies one sysctl (global, matched by exact Name, or per-interface,
// matched by Suffix against any Interface != "") against a baseline. Bad is
// nil for a purely informational rule: many sysctls in scope are genuinely
// context-dependent (ip_forward on a router/k8s node, disable_ipv6,
// tcp_congestion_control, conntrack timeout durations, bridge-nf-call-*, …)
// and have no single "correct" value across deployments — those are always
// reported with Severity "info" and never forced into a false pass/fail.
type Rule struct {
	Name      string // exact match for a global sysctl
	Suffix    string // suffix match (after the interface segment) for a per-interface sysctl
	Category  string
	Severity  string
	Bad       func(value string) bool
	Expected  string
	Rationale string
}

// Baseline holds every rule with a real (non-informational) severity
// judgment. Only well-established, unambiguous hardening baselines get a
// verdict here — see the package doc and docs/sysctl-audit.md for the
// deliberate scope boundary.
var Baseline = []Rule{
	{
		Suffix: "rp_filter", Category: CategorySecurity, Severity: SeverityCritical,
		Bad:       func(v string) bool { return v == "0" },
		Expected:  "1 (strict) or 2 (loose), never 0",
		Rationale: "rp_filter=0 disables source-address validation, allowing IP spoofing through this interface.",
	},
	{
		Suffix: "accept_redirects", Category: CategorySecurity, Severity: SeverityCritical,
		Bad:       func(v string) bool { return v == "1" },
		Expected:  "0",
		Rationale: "Accepting ICMP redirects lets an on-path attacker silently rewrite this host's routes.",
	},
	{
		Suffix: "secure_redirects", Category: CategorySecurity, Severity: SeverityCritical,
		Bad:       func(v string) bool { return v == "1" },
		Expected:  "0",
		Rationale: "secure_redirects narrows but does not close the ICMP-redirect route-rewrite risk; disable outright.",
	},
	{
		Suffix: "accept_source_route", Category: CategorySecurity, Severity: SeverityCritical,
		Bad:       func(v string) bool { return v == "1" },
		Expected:  "0",
		Rationale: "Source-routed packets let a sender dictate the return path, bypassing normal routing/firewall assumptions.",
	},
	{
		Name: "net.ipv4.tcp_syncookies", Category: CategorySecurity, Severity: SeverityCritical,
		Bad:       func(v string) bool { return v != "1" },
		Expected:  "1",
		Rationale: "SYN cookies are the kernel's primary defense against SYN-flood exhaustion of the listen backlog.",
	},
	{
		Name: "net.ipv4.tcp_sack", Category: CategoryTCP, Severity: SeverityWarning,
		Bad:       func(v string) bool { return v == "0" },
		Expected:  "1",
		Rationale: "Disabling SACK is almost always an accidental legacy setting; it hurts loss recovery, not security.",
	},
	{
		Name: "net.ipv4.tcp_timestamps", Category: CategoryTCP, Severity: SeverityWarning,
		Bad:       func(v string) bool { return v == "0" },
		Expected:  "1",
		Rationale: "Disabling timestamps removes RTT/PAWS support and is rarely an intentional choice.",
	},
	{
		Name: "net.ipv4.tcp_window_scaling", Category: CategoryTCP, Severity: SeverityWarning,
		Bad:       func(v string) bool { return v == "0" },
		Expected:  "1",
		Rationale: "Disabling window scaling caps throughput on any path with real bandwidth-delay product.",
	},
	{
		Suffix: "proxy_arp", Category: CategorySecurity, Severity: SeverityWarning,
		Bad:       func(v string) bool { return v == "1" },
		Expected:  "0 unless this host is intentionally proxying ARP",
		Rationale: "Proxy ARP is a deliberate, uncommon configuration; an unexpected 1 usually means it was left on by accident.",
	},
	{
		Suffix: "log_martians", Category: CategorySecurity, Severity: SeverityWarning,
		Bad:       func(v string) bool { return v == "0" },
		Expected:  "1",
		Rationale: "Logging martian packets is low-cost and gives early warning of spoofing/misconfiguration; usually worth enabling.",
	},
}

// Classify returns the finding for one collected entry: a Baseline verdict
// when a matching rule exists, otherwise an informational report with no
// pass/fail judgment.
func Classify(e models.SysctlAuditEntry) models.SysctlAuditFinding {
	for _, r := range Baseline {
		matched := (r.Name != "" && r.Name == e.Name) ||
			(r.Suffix != "" && e.Interface != "" && strings.HasSuffix(e.Name, "."+r.Suffix))
		if !matched {
			continue
		}
		if r.Bad(e.Value) {
			return models.SysctlAuditFinding{
				Severity: r.Severity, Category: e.Category, Name: e.Name, Interface: e.Interface,
				CurrentValue: e.Value, ExpectedValue: r.Expected, Rationale: r.Rationale,
			}
		}
		return models.SysctlAuditFinding{
			Severity: SeverityInfo, Category: e.Category, Name: e.Name, Interface: e.Interface,
			CurrentValue: e.Value, ExpectedValue: r.Expected, Rationale: "Matches the expected baseline.",
		}
	}
	return models.SysctlAuditFinding{
		Severity: SeverityInfo, Category: e.Category, Name: e.Name, Interface: e.Interface,
		CurrentValue: e.Value, Rationale: "No universal baseline for this sysctl; reported for visibility only.",
		Informational: true,
	}
}
