// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
)

// Intent is a coarse classification of an operator question so the
// heuristic engine can emphasise the matching slice of the snapshot.
type Intent string

const (
	IntentBrief      Intent = "brief"
	IntentDrops      Intent = "drops"
	IntentHealth     Intent = "health"
	IntentPolicy     Intent = "policy"
	IntentExposure   Intent = "exposure"
	IntentMode       Intent = "mode"
	IntentCongestion Intent = "congestion"
	IntentMetrics    Intent = "metrics"
)

// Classify maps a free-text question onto one Intent. Unknown or empty
// questions fall back to a cluster brief.
func Classify(question string) Intent {
	q := strings.ToLower(question)
	switch {
	case containsAny(q, "drop", "deny", "block", "reset", "rto", "kfree"):
		return IntentDrops
	case containsAny(q, "rtt", "latency", "retrans", "dns fail", "health", "score"):
		return IntentHealth
	case containsAny(q, "policy", "netpol", "allow-list", "allow list", "recommend", "draft"):
		return IntentPolicy
	case containsAny(q, "expos", "drift", "external", "internet", "egress"):
		return IntentExposure
	case containsAny(q, "enforce", "observe", "lease", "mode"):
		return IntentMode
	case containsAny(q, "metric", "anomal", "alert", "cpu", "memory", "disk", "spike"):
		return IntentMetrics
	default:
		return IntentBrief
	}
}

// Answer builds a Brief for a question. When p is non-nil and healthy it
// asks the provider to rewrite the heuristic brief; provider failures
// fall back to the heuristic brief instead of erroring the request.
//
// conversationID opts into short-lived multi-turn memory (conversation.go):
// when non-empty, prior turns under that id are fetched before answering
// and this exchange is recorded after, regardless of which engine
// answered. An empty conversationID behaves exactly as before this
// parameter existed — nothing is looked up or recorded.
func Answer(ctx context.Context, snap Snapshot, question string, p *Provider, conversationID string) Brief {
	base := BuildBrief(snap)
	base.Question = strings.TrimSpace(question)
	base.ConversationID = conversationID
	intent := Classify(question)
	base = specialize(base, snap, intent)
	history := conversationHistory(conversationID)

	if p == nil || !p.Enabled() {
		recordConversationTurn(conversationID, Turn{Question: base.Question, Summary: base.Summary})
		return base
	}
	rewritten, err := p.Rewrite(ctx, snap, base, question, history)
	if err != nil || strings.TrimSpace(rewritten) == "" {
		base.NextSteps = append([]string{"LLM rewrite unavailable; showing the heuristic brief."}, base.NextSteps...)
		recordConversationTurn(conversationID, Turn{Question: base.Question, Summary: base.Summary})
		return base
	}
	base.Summary = rewritten
	base.Engine = "llm"
	base.Model = p.Model
	recordConversationTurn(conversationID, Turn{Question: base.Question, Summary: base.Summary})
	return base
}

func specialize(b Brief, snap Snapshot, intent Intent) Brief {
	switch intent {
	case IntentDrops:
		b.Headline = "Drop and block picture"
		if len(snap.BlockReasons) > 0 {
			b.Summary = "Blocked traffic is attributed to: " + joinCounts(snap.BlockReasons) + ". " + b.Summary
		}
	case IntentHealth:
		b.Headline = "Network health"
		b.Summary = "Health score is " + itoa(snap.HealthScore) + "/100. " + b.Summary
	case IntentPolicy:
		b.Headline = "Policy drafts (review required)"
		b.Summary = itoa(snap.Recommendations) + " recommendation(s) are available. They are drafts only — plan then apply, never auto-enforce. " + b.Summary
	case IntentExposure:
		b.Headline = "Exposure and drift"
		b.Summary = itoa(snap.HighExposure) + " high-exposure item(s), " + itoa(snap.DriftFindings) + " drift finding(s), " + itoa(snap.ExternalEdges) + " external edges. " + b.Summary
	case IntentMode:
		b.Headline = "Fast-path mode"
		b.Summary = "Current mode is " + orDefault(snap.Mode, "observe") + ". Enforce is always lease-bounded and fails open. " + b.Summary
	case IntentCongestion:
		b.Headline = "Kernel network stack pressure"
		if snap.KernelCritical == 0 && snap.KernelWarnings == 0 {
			b.Summary = "No kernel-network congestion findings right now. " + b.Summary
		} else {
			b.Summary = itoa(snap.KernelCritical) + " critical and " + itoa(snap.KernelWarnings) + " warning kernel-network finding(s) across the stack. " + b.Summary
		}
	case IntentMetrics:
		b.Headline = "Metric alerts and anomalies"
		var alerts, anomalies []string
		for _, f := range snap.Metrics {
			if f.Kind == "metric-alert" {
				alerts = append(alerts, f.Message)
			} else {
				anomalies = append(anomalies, f.Message)
			}
		}
		lead := "No metric alerts are raised and no metric is anomalous right now. "
		if len(alerts) > 0 || len(anomalies) > 0 {
			lead = itoa(len(alerts)) + " metric alert(s) raised, " + itoa(len(anomalies)) + " anomalous metric(s). "
			if len(alerts) > 0 {
				lead += "Alerts: " + strings.Join(alerts, "; ") + ". "
			}
			if len(anomalies) > 0 {
				lead += "Most anomalous: " + strings.Join(anomalies, "; ") + ". "
			}
			b.NextSteps = append([]string{"Open the evidence for a metric (netractl metrics evidence CONTEXT --node N, or GET /api/v1/metrics/evidence) to see the flows, drops and captures behind it."}, b.NextSteps...)
		}
		b.Summary = lead + b.Summary
	}
	return b
}

// CongestionBrief builds a plain-English brief scoped to kernel-network
// congestion findings (the Congestion Map page), reusing BuildBrief's
// engine and specialize's existing intent-headline convention — see
// IntentDrops/IntentHealth above — rather than a bespoke prose path.
func CongestionBrief(snap Snapshot) Brief {
	return specialize(BuildBrief(snap), snap, IntentCongestion)
}

func containsAny(q string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(q, n) {
			return true
		}
	}
	return false
}

func joinCounts(in []NamedCount) string {
	parts := make([]string, 0, len(in))
	for i, n := range in {
		if i >= 5 {
			break
		}
		parts = append(parts, n.Name+"="+utoa(n.Count))
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string { return utoa(uint64(n)) }

func utoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
