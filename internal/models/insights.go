// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package models

import (
	"encoding/json"
	"time"
)

type ServicePortInfo struct {
	Name     string `json:"name,omitempty"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

type ServiceInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	ClusterIP string            `json:"clusterIP,omitempty"`
	Ports     []ServicePortInfo `json:"ports,omitempty"`
	Selector  map[string]string `json:"selector,omitempty"`
}

type DependencyNode struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"` // workload, pod, service, external
	Namespace    string `json:"namespace,omitempty"`
	Name         string `json:"name"`
	IP           string `json:"ip,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
}

type DependencyEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port,omitempty"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Blocked  uint64 `json:"blocked"`
	External bool   `json:"external,omitempty"`
}

type DependencyGraph struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Nodes       []DependencyNode `json:"nodes"`
	Edges       []DependencyEdge `json:"edges"`
}

type BlastRadiusNode struct {
	ID   string `json:"id"`
	Hops int    `json:"hops"`
}

type BlastRadiusResponse struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Root        string            `json:"root"`
	MaxHops     int               `json:"maxHops"`
	Nodes       []BlastRadiusNode `json:"nodes"`
	Edges       []DependencyEdge  `json:"edges"`
	Truncated   bool              `json:"truncated"`
	Caveat      string            `json:"caveat"`
}

type BehaviorBaselineEntry struct {
	Source string `json:"source"`
	Kind   string `json:"kind"` // destination, dns, sni, http-host, remote-port
	Value  string `json:"value"`
	Count  uint64 `json:"count,omitempty"`
}

type BehaviorBaseline struct {
	SchemaVersion int                     `json:"schemaVersion"`
	CapturedAt    time.Time               `json:"capturedAt"`
	Entries       []BehaviorBaselineEntry `json:"entries"`
}

type DriftFinding struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Value    string `json:"value"`
	Count    uint64 `json:"count,omitempty"`
	Message  string `json:"message"`
}

type DriftResponse struct {
	BaselineCapturedAt *time.Time     `json:"baselineCapturedAt,omitempty"`
	Findings           []DriftFinding `json:"findings"`
}

type PolicyRecommendation struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"` // cilium-egress-cnp
	Namespace    string          `json:"namespace"`
	WorkloadKind string          `json:"workloadKind,omitempty"`
	WorkloadName string          `json:"workloadName"`
	Confidence   string          `json:"confidence"`
	Rationale    []string        `json:"rationale"`
	Manifest     json.RawMessage `json:"manifest,omitempty"`
}

type InsightSummary struct {
	DependencyEdges      int  `json:"dependencyEdges"`
	ExternalEdges        int  `json:"externalEdges"`
	BaselineEntries      int  `json:"baselineEntries"`
	DriftFindings        int  `json:"driftFindings"`
	Recommendations      int  `json:"recommendations"`
	RateBaselineEntries  int  `json:"rateBaselineEntries"`
	RateDriftFindings    int  `json:"rateDriftFindings"`
	HighExposure         int  `json:"highExposure"`
	RemediationProposals int  `json:"remediationProposals"`
	RateWarming          bool `json:"rateWarming"`
}

type RateMetric struct {
	Source                 string  `json:"source"`
	WindowSeconds          float64 `json:"windowSeconds"`
	Samples                int     `json:"samples"`
	PacketsPerSecond       float64 `json:"packetsPerSecond"`
	BytesPerSecond         float64 `json:"bytesPerSecond"`
	BlockedPerSecond       float64 `json:"blockedPerSecond"`
	ConnectionsPerSecond   float64 `json:"connectionsPerSecond"`
	DNSQueriesPerSecond    float64 `json:"dnsQueriesPerSecond"`
	DNSFailuresPerSecond   float64 `json:"dnsFailuresPerSecond"`
	TLSHandshakesPerSecond float64 `json:"tlsHandshakesPerSecond"`
	HTTPRequestsPerSecond  float64 `json:"httpRequestsPerSecond"`
}

type RateWindow struct {
	GeneratedAt            time.Time    `json:"generatedAt"`
	RequestedWindowSeconds int64        `json:"requestedWindowSeconds"`
	Warming                bool         `json:"warming"`
	Metrics                []RateMetric `json:"metrics"`
}

type RateBaselineEntry struct {
	Source string  `json:"source"`
	Metric string  `json:"metric"`
	Rate   float64 `json:"rate"`
}

type RateBaseline struct {
	SchemaVersion int                 `json:"schemaVersion"`
	CapturedAt    time.Time           `json:"capturedAt"`
	WindowSeconds int64               `json:"windowSeconds"`
	Entries       []RateBaselineEntry `json:"entries"`
}

type RateFinding struct {
	Severity     string  `json:"severity"`
	Source       string  `json:"source"`
	Metric       string  `json:"metric"`
	BaselineRate float64 `json:"baselineRate"`
	CurrentRate  float64 `json:"currentRate"`
	Ratio        float64 `json:"ratio,omitempty"`
	Message      string  `json:"message"`
}

type RateDriftResponse struct {
	BaselineCapturedAt *time.Time    `json:"baselineCapturedAt,omitempty"`
	Window             RateWindow    `json:"window"`
	Findings           []RateFinding `json:"findings"`
}

type ExposureScore struct {
	Source               string   `json:"source"`
	Score                int      `json:"score"`
	Severity             string   `json:"severity"`
	ExternalDependencies int      `json:"externalDependencies"`
	BehaviorDrift        int      `json:"behaviorDrift"`
	RateDrift            int      `json:"rateDrift"`
	Reasons              []string `json:"reasons"`
}

type RemediationProposal struct {
	ID             string         `json:"id"`
	Source         string         `json:"source"`
	Severity       string         `json:"severity"`
	Kind           string         `json:"kind"`
	Title          string         `json:"title"`
	Rationale      []string       `json:"rationale"`
	Action         map[string]any `json:"action"`
	ReviewRequired bool           `json:"reviewRequired"`
}
