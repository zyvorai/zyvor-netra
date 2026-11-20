// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package playbook turns a report.Snapshot into review-only operator
// steps. Nothing here applies policy, captures a baseline, or extends a
// lease — each Step carries a suggested netractl/API action the human
// still has to run. AutoApply is always false.
package playbook

import (
	"fmt"
	"strings"

	"github.com/zyvorai/netra/internal/report"
)

// Step is one suggested action. IDs are stable so a UI can hide
// dismissed items without the server storing dismissal state.
type Step struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Rationale  string   `json:"rationale"`
	Command    string   `json:"command,omitempty"`
	API        string   `json:"api,omitempty"`
	Related    []string `json:"related,omitempty"`
	AutoApply  bool     `json:"autoApply"`
	ReviewOnly bool     `json:"reviewOnly"`
}

// Book is the briefing wrapper.
type Book struct {
	Headline string `json:"headline"`
	Count    int    `json:"count"`
	Steps    []Step `json:"steps"`
}

// Build derives steps from an already-built operator snapshot.
func Build(s report.Snapshot) Book {
	var steps []Step
	if s.StaleAgents > 0 {
		steps = append(steps, Step{
			ID:         "stale-agents",
			Severity:   "warning",
			Title:      "Restore agent coverage",
			Rationale:  fmt.Sprintf("%d node agent(s) are past the stale threshold. Hook coverage and counters from those nodes are incomplete.", s.StaleAgents),
			Command:    "netractl status",
			API:        "GET /api/v1/agents",
			ReviewOnly: true,
		})
	}
	if s.BaselineAt.IsZero() {
		steps = append(steps, Step{
			ID:         "capture-baseline",
			Severity:   "info",
			Title:      "Capture a behavior baseline",
			Rationale:  "Drift, recommendations, and several playbook steps stay empty until an operator explicitly accepts current destinations/DNS/SNI/HTTP as known-good.",
			Command:    "netractl insights baseline capture",
			API:        "POST /api/v1/insights/baseline",
			ReviewOnly: true,
		})
	}
	if s.RateBaselineAt.IsZero() {
		steps = append(steps, Step{
			ID:         "capture-rate-baseline",
			Severity:   "info",
			Title:      "Capture a rate baseline",
			Rationale:  "Rate-drift findings need two fresh agent windows plus an explicit rate baseline.",
			Command:    "netractl insights rate-baseline capture",
			API:        "POST /api/v1/insights/rate-baseline",
			ReviewOnly: true,
		})
	}
	if s.Mode == "enforce" {
		steps = append(steps, Step{
			ID:         "enforce-lease",
			Severity:   "warning",
			Title:      "Enforce lease is active",
			Rationale:  "Custom datapath denies are live and will fail open to observe when the lease expires, the agent cannot refresh, or HA leadership changes. Confirm the blast radius still matches intent.",
			Command:    "netractl ebpf mode observe",
			API:        "GET /api/v1/status",
			Related:    []string{"lease"},
			ReviewOnly: true,
		})
	}
	if s.HealthScore < 70 {
		steps = append(steps, Step{
			ID:         "health-floor",
			Severity:   severityForScore(s.HealthScore),
			Title:      fmt.Sprintf("Cluster health is %d/100", s.HealthScore),
			Rationale:  "The dashboard pulse treats 70 as a soft floor. Open Health and Path for TCP retransmit/RTO/SRTT and DNS failure ratio before reaching for a deny rule.",
			Command:    "netractl ebpf health",
			API:        "GET /api/v1/ebpf/health",
			ReviewOnly: true,
		})
	}
	if s.DriftFindings > 0 {
		steps = append(steps, Step{
			ID:         "review-drift",
			Severity:   "warning",
			Title:      fmt.Sprintf("Review %d behavior-drift finding(s)", s.DriftFindings),
			Rationale:  "New destinations, DNS names, SNI, or HTTP hosts appeared after the captured baseline. Recapture only if the current set is accepted as known-good.",
			Command:    "netractl insights drift",
			API:        "GET /api/v1/insights/drift",
			ReviewOnly: true,
		})
	}
	if s.RateDrift > 0 {
		steps = append(steps, Step{
			ID:         "review-rate-drift",
			Severity:   "warning",
			Title:      fmt.Sprintf("Review %d rate-drift finding(s)", s.RateDrift),
			Rationale:  "Current packets/bytes/DNS/connect rates crossed the 2×/5×/10× thresholds versus the captured rate baseline.",
			Command:    "netractl insights rate-drift",
			API:        "GET /api/v1/insights/rate-drift",
			ReviewOnly: true,
		})
	}
	if s.HighExposure > 0 {
		steps = append(steps, Step{
			ID:         "review-exposure",
			Severity:   "high",
			Title:      fmt.Sprintf("Review %d high-exposure source(s)", s.HighExposure),
			Rationale:  "Exposure combines external dependency edges with behavior and rate drift. Remediation proposals stay review-only.",
			Command:    "netractl insights exposure",
			API:        "GET /api/v1/insights/exposure",
			ReviewOnly: true,
		})
	}
	if s.Incidents > 0 {
		steps = append(steps, Step{
			ID:         "review-incidents",
			Severity:   "high",
			Title:      fmt.Sprintf("Inspect %d incident cluster(s)", s.Incidents),
			Rationale:  "Two or more independent signal kinds already agree on the same source. Start here instead of paging through Health, Insights, and Audit separately.",
			Command:    "netractl incidents",
			API:        "GET /api/v1/incidents",
			ReviewOnly: true,
		})
	}
	if s.DNSFailures > 0 && s.HealthScore < 85 {
		steps = append(steps, Step{
			ID:         "dns-failures",
			Severity:   "warning",
			Title:      fmt.Sprintf("%d matched cleartext DNS failures", s.DNSFailures),
			Rationale:  "UDP/53 rcode failures only. DoH/DoT/TCP DNS are intentionally not inferred. Use Path/Explain before blocking a resolver.",
			Command:    "netractl explain --all --dns",
			API:        "GET /api/v1/ebpf/health",
			ReviewOnly: true,
		})
	}
	if s.Blocked > 0 && s.Mode == "observe" {
		steps = append(steps, Step{
			ID:         "blocked-in-observe",
			Severity:   "info",
			Title:      fmt.Sprintf("%d blocked-packet counter(s) while mode is observe", s.Blocked),
			Rationale:  "Observe mode should not drop on Netra deny maps. Residual blocked counters usually come from a previous lease, XDP shield audit/enforce, or another program on the same hook. Confirm before assuming Netra is still denying.",
			Command:    "netractl ebpf summary",
			API:        "GET /api/v1/ebpf/summary",
			ReviewOnly: true,
		})
	}
	if len(steps) == 0 {
		steps = append(steps, Step{
			ID:         "quiet",
			Severity:   "info",
			Title:      "No operator action queued",
			Rationale:  "Agents are fresh, health is at or above the soft floor, and no drift/exposure/incident cluster is raised. Keep the baselines current after any intended change.",
			Command:    "netractl report",
			API:        "GET /api/v1/report",
			ReviewOnly: true,
		})
	}
	return Book{Headline: s.Headline, Count: len(steps), Steps: steps}
}

func severityForScore(score int) string {
	if score < 50 {
		return "critical"
	}
	return "warning"
}

// Markdown renders a Book for CLI/ticket paste.
func Markdown(b Book) string {
	var sb strings.Builder
	sb.WriteString("# Netra playbook\n\n")
	if b.Headline != "" {
		sb.WriteString("**" + b.Headline + "**\n\n")
	}
	for i, s := range b.Steps {
		fmt.Fprintf(&sb, "%d. **%s** (`%s`, %s)\n", i+1, s.Title, s.ID, s.Severity)
		fmt.Fprintf(&sb, "   %s\n", s.Rationale)
		if s.Command != "" {
			fmt.Fprintf(&sb, "   Suggested: `%s`\n", s.Command)
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Every step is review-only. Netra does not auto-apply playbook actions.\n")
	return sb.String()
}
