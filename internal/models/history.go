// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import "time"

// ClusterHealthSample is a bounded, in-memory-only point-in-time snapshot of
// overall cluster health, recorded by whichever handler happens to compute
// these values on a request (ebpfHealth, aiBrief/aiDigest, alert.Poller's
// tick). It is deliberately not persisted — see internal/store/history.go —
// consistent with this project's existing rate-sample history, which is also
// never resurrected across a restart.
type ClusterHealthSample struct {
	At          time.Time `json:"at"`
	HealthScore int       `json:"healthScore"`
	AgentsStale int       `json:"agentsStale"`
	Mode        string    `json:"mode"`
	Severity    string    `json:"severity"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

// HealthTrend is the result of internal/forecast.Project: a linear
// extrapolation of recent ClusterHealthSample history, estimating when the
// health score would cross BreachThreshold if the recent trend continued.
// TimeToBreachSeconds is nil whenever Project declines to project (too few
// samples, a flat/improving trend, too noisy a fit, or a horizon beyond
// MaxHorizon) — Note always explains why in that case.
type HealthTrend struct {
	GeneratedAt         time.Time `json:"generatedAt"`
	Samples             int       `json:"samples"`
	SpanSeconds         float64   `json:"spanSeconds,omitempty"`
	SlopePerHour        float64   `json:"slopePerHour,omitempty"`
	CurrentScore        int       `json:"currentScore"`
	BreachThreshold     int       `json:"breachThreshold"`
	TimeToBreachSeconds *float64  `json:"timeToBreachSeconds,omitempty"`
	// Confidence is "" (no projection), "low", or "medium" — never "high".
	Confidence string `json:"confidence,omitempty"`
	Note       string `json:"note"`
}

// TimelineEntry is one point in an internal/timeline.Build result: either an
// audit-log event rendered to a sentence, or a "digest-transition" marking a
// change in the AI on-call digest's fingerprint between two health samples.
// Severity is set only for digest-transition entries.
type TimelineEntry struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"` // "audit" or "digest-transition"
	Text     string    `json:"text"`
	Severity string    `json:"severity,omitempty"`
}

// Timeline is the result of internal/timeline.Build (and, optionally,
// internal/timeline.Narrate's LLM prose rewrite on top of it). Entries is
// always a complete, deterministic answer; Prose/Engine=="llm" are set only
// when a provider was configured and the rewrite succeeded.
type Timeline struct {
	GeneratedAt time.Time       `json:"generatedAt"`
	Since       *time.Time      `json:"since,omitempty"`
	Entries     []TimelineEntry `json:"entries"`
	Prose       string          `json:"prose,omitempty"`
	Engine      string          `json:"engine"` // "heuristic" or "llm"
}

// BlastRadiusItem is internal/insights.BlastRadius's per-removed-destination
// result for a policy review — a different, narrower concept from
// BlastRadiusResponse (the multi-hop dependency-graph traversal from
// GET /api/v1/insights/blast-radius): this one asks "does live traffic
// cross this specific destination a policy change would remove."
type BlastRadiusItem struct {
	Destination string `json:"destination"`
	// Kind is "cidr", "fqdn", "fqdn-pattern", "entity", or "unknown".
	Kind string `json:"kind"`
	// Correlated is true only for a "cidr" destination the dependency
	// graph could actually be checked against; false means the graph
	// structurally cannot answer this (FQDN/entity forms) or the CIDR
	// failed to parse — never treat Correlated:false as "no traffic."
	Correlated    bool   `json:"correlated"`
	ActiveTraffic bool   `json:"activeTraffic,omitempty"`
	Note          string `json:"note"`
}

// IncidentFinding is one signal folded into an IncidentCluster by
// internal/incident.Build.
type IncidentFinding struct {
	Kind     string `json:"kind"` // health, drift, rate-drift, exposure, detective, audit
	Severity string `json:"severity"`
	// JoinConfidence is "exact" when this finding's own Source/SourceKey
	// already matched the cluster's key directly, "probable" when it was
	// matched by best-effort IP or namespace/name resolution against the
	// live dependency graph (the same vocabulary internal/detective already
	// uses for its own confidence field, reused here for a related but
	// distinct meaning — see internal/incident's doc comment), and empty
	// for an audit or detective finding that couldn't be resolved to any
	// specific source at all (still included, never silently dropped,
	// under the "control-plane" pseudo-source).
	JoinConfidence string    `json:"joinConfidence,omitempty"`
	Subject        string    `json:"subject"`
	Message        string    `json:"message"`
	At             time.Time `json:"at"`
}

// IncidentCluster groups findings from different packages that share a
// SourceKey (see CanonicalSource). internal/incident.Build only returns a
// cluster once at least two distinct Findings[].Kind values contributed to
// it — a single-signal cluster is already visible on its own originating
// page/tool and isn't cross-signal correlation.
type IncidentCluster struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	SourceKey   string            `json:"sourceKey"`
	Subject     string            `json:"subject"`
	Severity    string            `json:"severity"`
	Findings    []IncidentFinding `json:"findings"`
}
