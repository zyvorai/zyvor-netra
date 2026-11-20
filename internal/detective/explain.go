// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package detective

import (
	"fmt"

	"github.com/zyvorai/netra/internal/models"
)

// UnifiedFinding is the single explain-a-drop shape for both the standalone
// eBPF path (always available) and Hubble/Cilium (only when configured),
// distinguished by Source. Standalone-eBPF is primary — see
// docs/standalone-ebpf.md — Hubble only ever enriches, never gates, a
// response.
type UnifiedFinding struct {
	Source      string `json:"source"` // "netra" | "hubble"
	Confidence  string `json:"confidence,omitempty"`
	Node        string `json:"node,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Pod         string `json:"pod,omitempty"`
	Code        string `json:"code"`
	Reason      string `json:"reason,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Src         string `json:"src,omitempty"`
	Dst         string `json:"dst,omitempty"`
	Packets     uint64 `json:"packets,omitempty"`
	Explanation string `json:"explanation"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// UnifiedExplainResponse is served by both GET /api/v1/ebpf/explain and
// GET /api/v1/drops/explain (repointed to the same handler/schema).
type UnifiedExplainResponse struct {
	Summary  models.DropDetectiveSummary `json:"summary"`
	Findings []UnifiedFinding            `json:"findings"`
	Sources  []string                    `json:"sources"`
}

// BuildUnified always runs the standalone Build path for Source: "netra"
// findings. hubbleFn is nil when no Cilium/Hubble client is configured (the
// common case per docs/standalone-ebpf.md's positioning) — then it's
// skipped entirely, never treated as an error. When hubbleFn is non-nil but
// returns an error (e.g. Hubble configured but temporarily unreachable),
// that's logged by the caller and otherwise ignored here: a broken Hubble
// integration degrades the response, it never fails it, since the
// standalone findings remain valid regardless.
func BuildUnified(agents []models.AgentStatus, cfg models.EBPFFastPathConfig, topN int, hubbleFn func() ([]UnifiedFinding, error)) (UnifiedExplainResponse, error) {
	base := Build(agents, cfg, topN)
	out := UnifiedExplainResponse{Summary: base.Summary, Sources: []string{"netra"}}
	out.Findings = make([]UnifiedFinding, 0, len(base.Findings))
	for _, f := range base.Findings {
		out.Findings = append(out.Findings, UnifiedFinding{
			Source: "netra", Confidence: f.Confidence, Node: f.Node,
			Namespace: f.Namespace, Pod: f.Pod,
			Code: f.Code, Reason: fmt.Sprintf("%d", f.Reason), Direction: directionName(f.Direction),
			Src: f.Src, Dst: f.Dst, Packets: f.Packets,
			Explanation: f.Explanation, Suggestion: f.Suggestion,
		})
	}
	if hubbleFn == nil {
		return out, nil
	}
	hubbleFindings, err := hubbleFn()
	if err != nil {
		return out, err
	}
	if len(hubbleFindings) > 0 {
		out.Findings = append(out.Findings, hubbleFindings...)
		out.Sources = append(out.Sources, "hubble")
	}
	return out, nil
}

func directionName(d uint8) string {
	if d == 1 {
		return "ingress"
	}
	return "egress"
}

// HubbleFindingsFromExplain adapts hubble.Explain's ad-hoc
// map[string]any shape (dropReason/summary/suggestions/flow, see
// internal/hubble.Explain and internal/api/server.go's former
// enrichExplanation) into UnifiedFinding, so the caller (internal/api)
// doesn't need its own translation layer.
func HubbleFindingsFromExplain(items []map[string]any) []UnifiedFinding {
	out := make([]UnifiedFinding, 0, len(items))
	for _, x := range items {
		f := UnifiedFinding{Source: "hubble"}
		if v, ok := x["dropReason"]; ok {
			f.Reason = fmt.Sprint(v)
			f.Code = fmt.Sprint(v)
		}
		if v, ok := x["summary"].(string); ok {
			f.Explanation = v
		}
		if sug, ok := x["suggestions"].([]string); ok && len(sug) > 0 {
			f.Suggestion = sug[0]
		}
		flow, _ := x["flow"].(map[string]any)
		if flow != nil {
			if src, ok := flow["source"].(map[string]any); ok {
				if ns, ok := src["namespace"].(string); ok {
					f.Namespace = ns
				}
				if pod, ok := src["podName"].(string); ok {
					f.Pod = pod
					f.Src = pod
				}
			}
			if dst, ok := flow["destination"].(map[string]any); ok {
				if pod, ok := dst["podName"].(string); ok {
					f.Dst = pod
				}
			}
			if v, ok := flow["verdict"].(string); ok {
				f.Direction = v
			}
		}
		if f.Code == "" {
			f.Code = "hubble-drop"
		}
		if f.Explanation == "" {
			f.Explanation = "Hubble reported a dropped flow."
		}
		out = append(out, f)
	}
	return out
}
