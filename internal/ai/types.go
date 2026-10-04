// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package ai turns already-computed Netra observability into operator-facing
// briefs and answers. It never sees packet payloads, argv, or cluster
// secrets. An optional OpenAI-compatible provider can rewrite the same
// compact snapshot into prose; when the provider is unset the package
// answers deterministically from the snapshot alone.
package ai

import "time"

// Snapshot is the only context an LLM is ever allowed to see. Fields are
// aggregates and short findings already produced by health/insights/eBPF
// summaries — not raw flows.
type Snapshot struct {
	GeneratedAt time.Time `json:"generatedAt"`

	AgentsTotal int `json:"agentsTotal"`
	AgentsStale int `json:"agentsStale"`
	Workloads   int `json:"workloads"`

	Mode         string `json:"mode,omitempty"`
	LeaseSeconds int64  `json:"leaseSeconds,omitempty"`

	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	Blocked uint64 `json:"blocked"`

	HealthScore int `json:"healthScore"`

	DependencyEdges int `json:"dependencyEdges"`
	ExternalEdges   int `json:"externalEdges"`
	DriftFindings   int `json:"driftFindings"`
	HighExposure    int `json:"highExposure"`
	Recommendations int `json:"recommendations"`

	// KernelCritical/KernelWarnings are the current kernel-network
	// (Congestion Map) finding counts, set only by the congestion-brief
	// path (internal/api/ai.go's aiCongestionBrief) — every other Snapshot
	// builder leaves these at zero, so IntentCongestion's summary text is
	// the only thing that reads them.
	KernelCritical int `json:"kernelCritical,omitempty"`
	KernelWarnings int `json:"kernelWarnings,omitempty"`

	TopDestinations []NamedCount `json:"topDestinations,omitempty"`
	TopDNS          []NamedCount `json:"topDns,omitempty"`
	TopProcesses    []NamedCount `json:"topProcesses,omitempty"`
	BlockReasons    []NamedCount `json:"blockReasons,omitempty"`
	TopICMP         []NamedCount `json:"topIcmp,omitempty"`
	Anomalies       []Finding    `json:"anomalies,omitempty"`
	Drift           []Finding    `json:"drift,omitempty"`
	Exposure        []Finding    `json:"exposure,omitempty"`
	// Metrics are raised metric alerts (Kind "metric-alert", Subject the
	// rule name) and the most anomalous per-second metrics (Kind
	// "metric-anomaly") from the metrics platform, when netrad runs it.
	Metrics       []Finding `json:"metrics,omitempty"`
	SuggestedNext []string  `json:"suggestedNext,omitempty"`
}

// NamedCount is a compact label/value pair used in top-N lists.
type NamedCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// Finding is a short, already-scored observation.
type Finding struct {
	Severity string `json:"severity,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Message  string `json:"message"`
}

// Brief is the structured answer returned by /api/v1/ai/brief and /ai/ask.
type Brief struct {
	Headline    string    `json:"headline"`
	Severity    string    `json:"severity"` // info | warning | critical
	Summary     string    `json:"summary"`
	Findings    []Finding `json:"findings"`
	NextSteps   []string  `json:"nextSteps"`
	Engine      string    `json:"engine"` // heuristic | llm
	Model       string    `json:"model,omitempty"`
	Question    string    `json:"question,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	GeneratedAt time.Time `json:"generatedAt"`
	Snapshot    Snapshot  `json:"snapshot"`
	// ConversationID echoes the AskRequest.ConversationID that was used
	// (empty if none was supplied) so a caller opting into conversation
	// memory knows what to send on its next turn. See conversation.go.
	ConversationID string `json:"conversationId,omitempty"`
}

// AskRequest is the JSON body for POST /api/v1/ai/ask.
type AskRequest struct {
	Question string `json:"question"`
	// Namespace optionally scopes the snapshot language; the controller
	// still builds a cluster-wide snapshot today and mentions the hint
	// in the prompt. Kept for forward compatibility with scoped packs.
	Namespace string `json:"namespace,omitempty"`
	// PreferLLM forces the optional provider path when configured.
	// Ignored when no provider is configured.
	PreferLLM bool `json:"preferLlm,omitempty"`
	// ConversationID opts into short-lived, bounded multi-turn memory
	// (conversation.go): when set, prior turns under this id are used to
	// resolve references in this question, and this question/answer is
	// appended to it. Omit for today's fully stateless behavior — this is
	// opt-in, not ambient.
	ConversationID string `json:"conversationId,omitempty"`
}

// ForgetRequest is the JSON body for POST /api/v1/ai/forget.
type ForgetRequest struct {
	ConversationID string `json:"conversationId"`
}

// Status describes whether the optional LLM rewrite path is live.
type Status struct {
	Enabled       bool   `json:"enabled"`
	Provider      string `json:"provider,omitempty"`
	Model         string `json:"model,omitempty"`
	HeuristicOnly bool   `json:"heuristicOnly"`
	Mutations     string `json:"mutations"`
}
