// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package models

import "time"

// KernelTunable is a read-only snapshot of one networking sysctl. Value is
// deliberately kept as text because several important controls are vectors
// (tcp_rmem/tcp_wmem/tcp_mem), bitmaps, algorithms, or qdisc names.
type KernelTunable struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// KernelNetworkCounter is a cumulative kernel counter from /proc/net/snmp or
// /proc/net/netstat. These counters reset on node boot; the API must not
// present them as rates without two samples and elapsed time.
type KernelNetworkCounter struct {
	Name   string `json:"name"`
	Value  uint64 `json:"value"`
	Source string `json:"source"`
}

type KernelNetworkSnapshot struct {
	Tunables []KernelTunable        `json:"tunables,omitempty"`
	Counters []KernelNetworkCounter `json:"counters,omitempty"`
}

// KernelNetworkFinding connects observed drop/congestion evidence to the
// kernel layer that can produce it. ApplyCommand is guidance only: Netra never
// writes sysctls automatically. RollbackCommand restores the value observed in
// this report, making every suggestion reviewable and reversible.
type KernelNetworkFinding struct {
	Severity        string   `json:"severity"`
	Layer           string   `json:"layer"`
	Signal          string   `json:"signal"`
	Evidence        []string `json:"evidence"`
	Explanation     string   `json:"explanation"`
	Recommendation  string   `json:"recommendation"`
	Tunable         string   `json:"tunable,omitempty"`
	CurrentValue    string   `json:"currentValue,omitempty"`
	SuggestedValue  string   `json:"suggestedValue,omitempty"`
	ApplyCommand    string   `json:"applyCommand,omitempty"`
	RollbackCommand string   `json:"rollbackCommand,omitempty"`
	Risk            string   `json:"risk"`
	WindowSeconds   float64  `json:"windowSeconds,omitempty"`
}

type KernelNetworkCounterDelta struct {
	Name      string  `json:"name"`
	Delta     uint64  `json:"delta"`
	PerSecond float64 `json:"perSecond"`
}

// KernelNetworkWindow is computed by the controller from two agent reports.
// It turns boot-lifetime counters into interval evidence and explicitly marks
// restarts/resets instead of interpreting a backwards counter as zero loss.
type KernelNetworkWindow struct {
	Node               string                      `json:"node"`
	StartAt            time.Time                   `json:"startAt,omitempty"`
	EndAt              time.Time                   `json:"endAt,omitempty"`
	Seconds            float64                     `json:"seconds,omitempty"`
	Warming            bool                        `json:"warming"`
	ResetDetected      bool                        `json:"resetDetected,omitempty"`
	ResetSignals       []string                    `json:"resetSignals,omitempty"`
	Counters           []KernelNetworkCounterDelta `json:"counters,omitempty"`
	SoftnetDropped     uint64                      `json:"softnetDropped"`
	SoftnetDroppedRate float64                     `json:"softnetDroppedPerSecond"`
	SoftnetTimeSqueeze uint64                      `json:"softnetTimeSqueeze"`
	SoftnetSqueezeRate float64                     `json:"softnetTimeSqueezePerSecond"`
	RXDropped          uint64                      `json:"rxDropped"`
	RXDroppedRate      float64                     `json:"rxDroppedPerSecond"`
	TXDropped          uint64                      `json:"txDropped"`
	TXDroppedRate      float64                     `json:"txDroppedPerSecond"`
	RXMissed           uint64                      `json:"rxMissed"`
	RXMissedRate       float64                     `json:"rxMissedPerSecond"`
	QdiscDrops         uint64                      `json:"qdiscDrops"`
	QdiscDropsRate     float64                     `json:"qdiscDropsPerSecond"`
}

type NodeKernelNetworkDiagnostics struct {
	Node     string                 `json:"node"`
	Snapshot KernelNetworkSnapshot  `json:"snapshot"`
	Window   *KernelNetworkWindow   `json:"window,omitempty"`
	Findings []KernelNetworkFinding `json:"findings,omitempty"`
}

type KernelNetworkDiagnosticsSummary struct {
	Nodes    int `json:"nodes"`
	Findings int `json:"findings"`
	Critical int `json:"critical"`
	Warnings int `json:"warnings"`
	Warming  int `json:"warming"`
}

type KernelNetworkDiagnosticsResponse struct {
	Summary     KernelNetworkDiagnosticsSummary `json:"summary"`
	Nodes       []NodeKernelNetworkDiagnostics  `json:"nodes"`
	Limitations []string                        `json:"limitations"`
}
