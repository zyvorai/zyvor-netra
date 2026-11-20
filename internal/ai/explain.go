// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
)

// ExplainRequest is a structured finding from Health, Drops, or Insights
// that the UI wants narrated against the live snapshot.
type ExplainRequest struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject,omitempty"`
	Message   string `json:"message,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Page      string `json:"page,omitempty"`
	Question  string `json:"question,omitempty"`
	PreferLLM bool   `json:"preferLlm,omitempty"`
}

// ExplainQuestion builds a deterministic question from a page finding so
// Ask/LLM paths stay consistent with chip clicks.
func ExplainQuestion(req ExplainRequest) string {
	if strings.TrimSpace(req.Question) != "" {
		return strings.TrimSpace(req.Question)
	}
	parts := make([]string, 0, 4)
	parts = append(parts, "Explain this Netra finding")
	if req.Page != "" {
		parts = append(parts, "from the "+req.Page+" page")
	}
	if req.Kind != "" {
		parts = append(parts, "kind="+req.Kind)
	}
	if req.Subject != "" {
		parts = append(parts, "subject="+req.Subject)
	}
	if req.Message != "" {
		parts = append(parts, "— "+req.Message)
	}
	return strings.Join(parts, " ")
}

// ExplainFinding narrates one page finding against the live snapshot.
// Unlike Answer(ExplainQuestion(...)), it ranks related snapshot findings
// and page-specific next steps before any optional LLM rewrite.
func ExplainFinding(ctx context.Context, snap Snapshot, req ExplainRequest, p *Provider) Brief {
	base := BuildBrief(snap)
	base.Question = ExplainQuestion(req)
	base.Headline = explainHeadline(req)
	related := relatedFindings(snap, req)
	if len(related) > 0 {
		base.Findings = append(related, base.Findings...)
		if len(base.Findings) > 12 {
			base.Findings = base.Findings[:12]
		}
	}
	lead := explainLead(req, related)
	base.Summary = lead + base.Summary
	base.NextSteps = append(explainNextSteps(req), base.NextSteps...)
	if req.Severity != "" {
		base.Severity = worseSeverity(base.Severity, req.Severity)
	}

	if p == nil || !p.Enabled() {
		return base
	}
	rewritten, err := p.Rewrite(ctx, snap, base, base.Question, nil)
	if err != nil || strings.TrimSpace(rewritten) == "" {
		base.NextSteps = append([]string{"LLM rewrite unavailable; showing the heuristic explanation."}, base.NextSteps...)
		return base
	}
	base.Summary = rewritten
	base.Engine = "llm"
	base.Model = p.Model
	return base
}

func explainHeadline(req ExplainRequest) string {
	if req.Kind != "" {
		return "Finding: " + req.Kind
	}
	if req.Page != "" {
		return "Finding from " + req.Page
	}
	return "Finding explanation"
}

func explainLead(req ExplainRequest, related []Finding) string {
	msg := strings.TrimSpace(req.Message)
	if msg == "" {
		msg = "No message was supplied with this finding."
	}
	lead := "This finding says: " + msg + ". "
	if req.Subject != "" {
		lead = "Subject " + req.Subject + ". " + lead
	}
	if len(related) > 0 {
		lead += "Related live signals: "
		parts := make([]string, 0, len(related))
		for i, f := range related {
			if i >= 3 {
				break
			}
			parts = append(parts, f.Message)
		}
		lead += strings.Join(parts, "; ") + ". "
	} else {
		lead += "No closely matching live signals in the current snapshot. "
	}
	return lead
}

func explainNextSteps(req ExplainRequest) []string {
	page := strings.ToLower(req.Page)
	kind := strings.ToLower(req.Kind)
	switch {
	case page == "drops" || strings.Contains(kind, "drop") || strings.Contains(kind, "deny"):
		return []string{
			"Open Drops / Diagnose (netractl ebpf diagnose) and compare Hubble vs Netra deny/NetPol/Shield reasons.",
			"If the scope is clear, preview a deny with netractl ebpf deny-preview — never apply from Ask Netra.",
		}
	case page == "metrics" || page == "metric-alerts" || page == "metric-anomalies" || strings.Contains(kind, "metric"):
		return []string{
			"Open Metrics evidence for the chart window (GET /api/v1/metrics/evidence) to see flows, drops and captures behind it.",
		}
	case page == "tls" || page == "tls-fingerprints" || page == "surfaces" || page == "encrypted-dns" ||
		strings.Contains(kind, "ja3") || strings.Contains(kind, "tls") || strings.Contains(kind, "ech"):
		return []string{
			"Open TLS / JA3 risk and Detect to correlate rare fingerprints with DNS/scan findings — observe only.",
		}
	case page == "investigate" || page == "flow-observe" || strings.Contains(kind, "investigate"):
		return []string{
			"Open Investigate (#page=investigate) or Flow observe; gaps listed by the API are visibility boundaries, not missing proof of delivery.",
		}
	case page == "shadow-saas" || page == "ai-destinations" || strings.Contains(kind, "shadow") || strings.Contains(kind, "genai"):
		return []string{
			"Open Surfaces → Shadow SaaS / AI destinations. Catalog matches are hostname metadata only — no payload DPI.",
		}
	case page == "netlink" || strings.Contains(kind, "netlink") || strings.Contains(kind, "route"):
		return []string{
			"Open Netlink (view=state) for requester attribution (comm/pid/cgroup) — read-only RTNL observation.",
		}
	case page == "congestion" || strings.Contains(kind, "kernel-network") || strings.Contains(kind, "congestion"):
		return []string{
			"Open Congestion Map or GET /api/v1/ai/congestion-brief for stack-layer pressure.",
		}
	case page == "security-review" || strings.Contains(kind, "intel") || strings.Contains(kind, "scan") || strings.Contains(kind, "dns"):
		return []string{
			"Correlate on Security Review / Detect. Leased auto-mitigate stays inert without an enforce lease.",
		}
	default:
		return []string{
			"Ask Netra a follow-up question, or open Investigate for a fused connection timeline.",
		}
	}
}

func relatedFindings(snap Snapshot, req ExplainRequest) []Finding {
	needle := strings.ToLower(strings.Join([]string{req.Kind, req.Subject, req.Message, req.Page}, " "))
	pools := [][]Finding{snap.Anomalies, snap.Drift, snap.Exposure, snap.Metrics}
	out := make([]Finding, 0, 4)
	for _, pool := range pools {
		for _, f := range pool {
			hay := strings.ToLower(f.Kind + " " + f.Subject + " " + f.Message)
			if needle != "" && (strings.Contains(hay, strings.ToLower(req.Kind)) ||
				(req.Subject != "" && strings.Contains(hay, strings.ToLower(req.Subject))) ||
				strings.Contains(hay, strings.ToLower(req.Page))) {
				out = append(out, f)
				if len(out) >= 4 {
					return out
				}
			}
		}
	}
	_ = needle
	return out
}

func worseSeverity(a, b string) string {
	rank := func(s string) int {
		switch strings.ToLower(s) {
		case "critical":
			return 3
		case "warning":
			return 2
		default:
			return 1
		}
	}
	if rank(b) > rank(a) {
		return strings.ToLower(b)
	}
	return a
}
