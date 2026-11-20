// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"fmt"
	"strings"
	"time"
)

// BuildBrief produces a deterministic operator brief from a Snapshot.
// This is the default path and the fallback when no LLM is configured.
func BuildBrief(snap Snapshot) Brief {
	if snap.GeneratedAt.IsZero() {
		snap.GeneratedAt = time.Now().UTC()
	}
	findings := collectFindings(snap)
	sev := rollupSeverity(findings)
	if sev == "" {
		sev = "info"
	}
	headline := headlineFor(snap, sev)
	summary := summaryFor(snap, sev, findings)
	next := snap.SuggestedNext
	if len(next) == 0 {
		next = defaultNextSteps(snap, sev)
	}
	b := Brief{
		Headline:    headline,
		Severity:    sev,
		Summary:     summary,
		Findings:    capFindings(findings, 12),
		NextSteps:   next,
		Engine:      "heuristic",
		GeneratedAt: snap.GeneratedAt,
		Snapshot:    snap,
	}
	b.Fingerprint = Fingerprint(snap, sev)
	return b
}

func collectFindings(snap Snapshot) []Finding {
	out := make([]Finding, 0, len(snap.Anomalies)+len(snap.Drift)+len(snap.Exposure)+len(snap.Metrics)+4)
	out = append(out, snap.Anomalies...)
	out = append(out, snap.Drift...)
	out = append(out, snap.Exposure...)
	out = append(out, snap.Metrics...)
	if snap.AgentsStale > 0 {
		out = append(out, Finding{
			Severity: "warning",
			Kind:     "stale-agent",
			Subject:  "control-plane",
			Message:  fmt.Sprintf("%d of %d node agents are stale", snap.AgentsStale, snap.AgentsTotal),
		})
	}
	if strings.EqualFold(snap.Mode, "enforce") {
		out = append(out, Finding{
			Severity: "warning",
			Kind:     "enforce-lease",
			Subject:  "fast-path",
			Message:  fmt.Sprintf("fast path is in enforce mode (lease %ds) and will revert to observe when the lease expires", snap.LeaseSeconds),
		})
	}
	if snap.Blocked > 0 {
		out = append(out, Finding{
			Severity: "info",
			Kind:     "blocked-packets",
			Subject:  "datapath",
			Message:  fmt.Sprintf("%d packets counted as blocked across reporting agents", snap.Blocked),
		})
	}
	return out
}

func rollupSeverity(findings []Finding) string {
	sev := "info"
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			return "critical"
		case "warning", "high":
			sev = "warning"
		}
	}
	return sev
}

func headlineFor(snap Snapshot, sev string) string {
	switch sev {
	case "critical":
		return "Critical network health or exposure findings need review"
	case "warning":
		if snap.AgentsStale > 0 {
			return "Agents stale or traffic anomalies present"
		}
		return "Network anomalies present — observe-first review recommended"
	default:
		if snap.AgentsTotal == 0 {
			return "No node agents reporting"
		}
		return "Cluster network looks quiet"
	}
}

func summaryFor(snap Snapshot, sev string, findings []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d agents (%d stale), %d workloads, health score %d/100. ",
		snap.AgentsTotal, snap.AgentsStale, snap.Workloads, snap.HealthScore)
	fmt.Fprintf(&b, "Fast-path mode %s. ", orDefault(snap.Mode, "observe"))
	fmt.Fprintf(&b, "%d dependency edges (%d external), %d drift findings, %d high-exposure items, %d policy drafts. ",
		snap.DependencyEdges, snap.ExternalEdges, snap.DriftFindings, snap.HighExposure, snap.Recommendations)
	if len(findings) == 0 {
		b.WriteString("No scored anomalies in the current snapshot.")
		return b.String()
	}
	fmt.Fprintf(&b, "Top finding: %s", findings[0].Message)
	return b.String()
}

func defaultNextSteps(snap Snapshot, sev string) []string {
	steps := make([]string, 0, 6)
	if snap.AgentsTotal == 0 {
		return []string{
			"Confirm netra-agent is running on each node and can reach the controller.",
			"Run netra-doctor on a node to check host readiness.",
		}
	}
	if snap.AgentsStale > 0 {
		steps = append(steps, "Inspect stale agents on Overview / GET /api/v1/agents before trusting live counters.")
	}
	if sev != "info" {
		steps = append(steps, "Open Health and Drops pages (or netra_ebpf_health / netra_ebpf_diagnose) and confirm the finding against raw counters.")
	}
	if snap.Recommendations > 0 {
		steps = append(steps, "Review GET /api/v1/insights/recommendations — drafts only; plan then apply, never auto-enforce.")
	}
	if strings.EqualFold(snap.Mode, "enforce") {
		steps = append(steps, "Enforce is lease-bounded. Do not renew the lease unless the deny set is still intended.")
	}
	steps = append(steps, "Do not paste packet payloads, Secrets, or API keys into this brief — Netra does not collect them and the AI layer must not invent them.")
	return steps
}

func capFindings(in []Finding, n int) []Finding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
