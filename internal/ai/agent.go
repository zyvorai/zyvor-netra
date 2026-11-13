// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
)

// AgentStep is one node in the in-process natural-language graph.
// The controller graph is stdlib-only; the optional Python LangGraph
// companion in python/netra_langgraph/ is a separate process that calls
// these same HTTP endpoints as tools.
type AgentStep struct {
	Node   string `json:"node"`
	Detail string `json:"detail,omitempty"`
}

// AgentResult is the payload for POST /api/v1/ai/agent.
// It is still read-only: a draft, if present, is a preview.
type AgentResult struct {
	Brief          Brief       `json:"brief"`
	Intent         Intent      `json:"intent"`
	Draft          *RuleDraft  `json:"draft,omitempty"`
	Suggestions    []string    `json:"suggestions,omitempty"`
	Steps          []AgentStep `json:"steps"`
	Engine         string      `json:"engine"`
	ConversationID string      `json:"conversationId,omitempty"`
	// Evidence is a capped, intent-specific pull from the snapshot
	// (gather step). Never payloads or argv — aggregates only.
	Evidence []Finding `json:"evidence,omitempty"`
}

// Run walks the in-process NL graph:
//
//	classify → gather → (optional draft) → synthesize
//
// Provider failures fall back to the heuristic brief, same contract as Answer.
func Run(ctx context.Context, snap Snapshot, question string, p *Provider, conversationID string) AgentResult {
	out := AgentResult{
		Steps:          make([]AgentStep, 0, 6),
		ConversationID: conversationID,
	}

	q := strings.TrimSpace(question)
	intent := Classify(q)
	out.Intent = intent
	out.Steps = append(out.Steps, AgentStep{Node: "classify", Detail: string(intent)})

	evidence, gatherDetail := gatherEvidence(snap, intent)
	out.Evidence = evidence
	out.Steps = append(out.Steps, AgentStep{Node: "gather", Detail: gatherDetail})

	if looksLikeRule(q) {
		d := DraftRule(q)
		out.Steps = append(out.Steps, AgentStep{
			Node:   "draft",
			Detail: draftDetail(d),
		})
		if d.Understood {
			cp := d
			out.Draft = &cp
		}
	}

	out.Steps = append(out.Steps, AgentStep{Node: "synthesize", Detail: "answer from snapshot"})
	brief := Answer(ctx, snap, q, p, conversationID)
	if len(evidence) > 0 && brief.Engine == "heuristic" {
		brief.Findings = append(evidence, brief.Findings...)
		if len(brief.Findings) > 12 {
			brief.Findings = brief.Findings[:12]
		}
	}
	if intent == IntentInvestigate {
		brief.NextSteps = append([]string{
			"Open Investigate (#page=investigate) or run netractl investigate connection with namespace/pod/peer/port.",
			"POST /api/v1/investigate/connection composes DNS→flow→netlink→policy→drops with an explicit visibility gap.",
		}, brief.NextSteps...)
	}
	out.Brief = brief
	out.Engine = brief.Engine
	out.Suggestions = Suggestions(snap)
	if out.Brief.ConversationID == "" {
		out.Brief.ConversationID = conversationID
	}
	return out
}

// gatherEvidence pulls a capped, intent-specific slice of the snapshot so
// the step trace shows what the agent looked at. Stdlib-only; no HTTP.
func gatherEvidence(snap Snapshot, intent Intent) ([]Finding, string) {
	const capN = 4
	take := func(in []Finding, n int) []Finding {
		if len(in) > n {
			return append([]Finding(nil), in[:n]...)
		}
		return append([]Finding(nil), in...)
	}
	switch intent {
	case IntentDrops:
		out := take(snap.Anomalies, capN)
		if len(snap.BlockReasons) > 0 {
			out = append(out, Finding{Kind: "block-reason", Subject: snap.BlockReasons[0].Name, Message: "top block reason count=" + utoa(snap.BlockReasons[0].Count)})
		}
		return out, "drops/anomalies"
	case IntentHealth:
		return take(snap.Anomalies, capN), "health/anomalies"
	case IntentExposure:
		out := take(snap.Exposure, capN)
		out = append(out, take(snap.Drift, capN-len(out))...)
		return out, "exposure/drift"
	case IntentPolicy:
		if snap.Recommendations > 0 {
			return []Finding{{Kind: "policy", Message: itoa(snap.Recommendations) + " recommendation draft(s) need review"}}, "recommendations"
		}
		return nil, "recommendations-empty"
	case IntentCongestion:
		if snap.KernelCritical+snap.KernelWarnings == 0 {
			return nil, "congestion-quiet"
		}
		return []Finding{{
			Kind:    "congestion",
			Message: itoa(snap.KernelCritical) + " critical / " + itoa(snap.KernelWarnings) + " warning kernel-network finding(s)",
		}}, "congestion"
	case IntentMetrics:
		return take(snap.Metrics, capN), "metric-alerts/anomalies"
	case IntentInvestigate:
		out := take(snap.Anomalies, 2)
		out = append(out, take(snap.BlockReasonsToFindings(), 2)...)
		return out, "investigate-hints"
	case IntentMode:
		return []Finding{{Kind: "mode", Message: "mode=" + orDefault(snap.Mode, "observe")}}, "mode"
	default:
		out := take(snap.Anomalies, 2)
		out = append(out, take(snap.Metrics, 2)...)
		return out, "brief-core"
	}
}

// BlockReasonsToFindings adapts NamedCount block reasons into Findings
// for gather Evidence without inventing severities.
func (snap Snapshot) BlockReasonsToFindings() []Finding {
	out := make([]Finding, 0, len(snap.BlockReasons))
	for _, b := range snap.BlockReasons {
		out = append(out, Finding{Kind: "block-reason", Subject: b.Name, Message: "count=" + utoa(b.Count)})
	}
	return out
}

func looksLikeRule(q string) bool {
	if q == "" {
		return false
	}
	ql := strings.ToLower(q)
	return containsAny(ql, "deny", "block", "drop", "rate", "limit", "throttle", "ban", "forbid", "allow", "except", "whitelist", "exception")
}

func draftDetail(d RuleDraft) string {
	if !d.Understood {
		return "not-understood"
	}
	if d.Kind != "" {
		return d.Kind + "/" + d.Confidence
	}
	return d.Confidence
}
