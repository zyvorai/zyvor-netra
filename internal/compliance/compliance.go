// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package compliance maps existing sysctl-audit findings into CIS-ish
// network posture packs. Review-only — Netra never writes sysctls.
package compliance

import (
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/sysctlaudit"
)

// Control is one mapped check inside a pack.
type Control struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	CISRef      string `json:"cisRef,omitempty"`
	Status      string `json:"status"` // pass | fail | warn | info | unknown
	Severity    string `json:"severity,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Nodes       int    `json:"nodes,omitempty"`
}

// Pack is a named compliance view over live sysctl audit.
type Pack struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	GeneratedAt time.Time `json:"generatedAt"`
	Controls    []Control `json:"controls"`
	Passed      int       `json:"passed"`
	Failed      int       `json:"failed"`
	Warned      int       `json:"warned"`
	Note        string    `json:"note"`
}

// Report is GET /api/v1/compliance.
type Report struct {
	GeneratedAt   time.Time                 `json:"generatedAt"`
	Packs         []Pack                    `json:"packs"`
	SysctlSummary models.SysctlAuditSummary `json:"sysctlSummary"`
	Note          string                    `json:"note"`
}

// Build evaluates the network-hardening pack from agent sysctl snapshots.
func Build(agents []models.AgentStatus, topN int) Report {
	now := time.Now().UTC()
	audit := sysctlaudit.Build(agents, topN)
	pack := networkHardeningPack(audit, now)
	return Report{
		GeneratedAt:   now,
		Packs:         []Pack{pack},
		SysctlSummary: audit.Summary,
		Note:          "CIS-inspired network posture from existing sysctl audit — not a certified CIS assessor. Review-only.",
	}
}

func networkHardeningPack(audit models.SysctlAuditResponse, now time.Time) Pack {
	// Aggregate findings by control key (sysctl suffix / name).
	type agg struct {
		sev   string
		count int
		msg   string
		nodes map[string]bool
	}
	byKey := map[string]*agg{}
	for _, n := range audit.Nodes {
		for _, f := range n.Findings {
			key := controlKey(f)
			a := byKey[key]
			if a == nil {
				a = &agg{nodes: map[string]bool{}}
				byKey[key] = a
			}
			a.count++
			a.nodes[n.Node] = true
			if sevRank(f.Severity) >= sevRank(a.sev) {
				a.sev = f.Severity
				a.msg = f.Name + "=" + f.CurrentValue
				if f.Rationale != "" {
					a.msg = f.Rationale + " (" + a.msg + ")"
				}
			}
		}
	}

	defs := []struct {
		id, title, cis, keySuffix string
		wantPassWhenMissing       bool
	}{
		{"net-rp-filter", "IPv4 rp_filter enabled", "CIS Linux 3.3.7 (network)", "rp_filter", false},
		{"net-no-redirects", "ICMP redirects not accepted", "CIS Linux 3.3.2", "accept_redirects", false},
		{"net-no-source-route", "Source routing disabled", "CIS Linux 3.3.1", "accept_source_route", false},
		{"net-syncookies", "TCP SYN cookies enabled", "CIS Linux 3.3.8", "tcp_syncookies", false},
		{"net-ignore-broadcasts", "Ignore ICMP broadcast echo", "CIS Linux 3.3.3", "icmp_echo_ignore_broadcasts", false},
		{"net-bogus-icmp", "Ignore bogus ICMP error responses", "CIS Linux 3.3.4", "icmp_ignore_bogus_error_responses", false},
		{"net-log-martians", "Log martian packets", "CIS Linux 3.3.6", "log_martians", false},
	}

	p := Pack{
		ID: "network-hardening", Title: "Network hardening (CIS-inspired)",
		Description: "Maps Netra sysctl-audit security findings to common CIS Linux network controls.",
		GeneratedAt: now,
		Note:        "Pass = no critical/warning finding for that control on fresh agents.",
	}
	for _, d := range defs {
		c := Control{ID: d.id, Title: d.title, CISRef: d.cis, Status: "pass"}
		var hit *agg
		for k, a := range byKey {
			if strings.Contains(k, d.keySuffix) {
				if hit == nil || sevRank(a.sev) > sevRank(hit.sev) {
					hit = a
				}
			}
		}
		if hit != nil && (hit.sev == sysctlaudit.SeverityCritical || hit.sev == sysctlaudit.SeverityWarning) {
			c.Status = "fail"
			if hit.sev == sysctlaudit.SeverityWarning {
				c.Status = "warn"
			}
			c.Severity = hit.sev
			c.Evidence = hit.msg
			c.Nodes = len(hit.nodes)
			c.Remediation = "Review sysctl on affected nodes (Netra does not write sysctls). See docs/sysctl-audit.md."
			if c.Status == "fail" {
				p.Failed++
			} else {
				p.Warned++
			}
		} else {
			p.Passed++
			c.Evidence = "no critical/warning sysctl-audit finding for this control"
		}
		p.Controls = append(p.Controls, c)
	}
	return p
}

func controlKey(f models.SysctlAuditFinding) string {
	s := strings.ToLower(f.Name)
	if f.Interface != "" {
		s += "|" + f.Interface
	}
	return s
}

func sevRank(s string) int {
	switch s {
	case sysctlaudit.SeverityCritical:
		return 3
	case sysctlaudit.SeverityWarning:
		return 2
	case sysctlaudit.SeverityInfo, "informational":
		return 1
	default:
		return 0
	}
}
