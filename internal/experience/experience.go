// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package experience builds a workload digital-experience scorecard from
// existing Netra signals (connect latency, TCP retrans/RTO, DNS failures).
// No endpoint agent — workload-path DX for cluster workloads.
package experience

import (
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// WorkloadScore is one workload's DX summary.
type WorkloadScore struct {
	Namespace    string   `json:"namespace,omitempty"`
	Pod          string   `json:"pod,omitempty"`
	WorkloadKind string   `json:"workloadKind,omitempty"`
	WorkloadName string   `json:"workloadName,omitempty"`
	Node         string   `json:"node,omitempty"`
	Score        int      `json:"score"` // 0-100, higher = healthier
	Severity     string   `json:"severity"`
	SLOBreached  bool     `json:"sloBreached,omitempty"`
	AvgConnectUS uint64   `json:"avgConnectUs,omitempty"`
	MaxConnectUS uint64   `json:"maxConnectUs,omitempty"`
	Retransmits  uint64   `json:"retransmissions,omitempty"`
	RTOs         uint64   `json:"rtos,omitempty"`
	DNSFailures  uint64   `json:"dnsFailures,omitempty"`
	DNSQueries   uint64   `json:"dnsQueries,omitempty"`
	Signals      []string `json:"signals,omitempty"`
}

// Result is GET /api/v1/insights/experience.
type Result struct {
	Workloads   []WorkloadScore `json:"workloads"`
	Count       int             `json:"count"`
	Degraded    int             `json:"degraded"`
	SLOBreaches int             `json:"sloBreaches"`
	Capped      bool            `json:"capped"`
	Note        string          `json:"note"`
}

const MaxRows = 200

type key struct {
	ns, pod, kind, name, node string
}

type agg struct {
	connectEstablished uint64
	connectTotalUS     uint64
	connectMaxUS       uint64
	retrans            uint64
	rtos               uint64
	dnsFail            uint64
	dnsQ               uint64
}

// Build aggregates per-workload DX from agent reports.
func Build(agents []models.AgentStatus, limit int) Result {
	if limit <= 0 || limit > MaxRows {
		limit = MaxRows
	}
	by := map[key]*agg{}
	ensure := func(k key) *agg {
		if a := by[k]; a != nil {
			return a
		}
		a := &agg{}
		by[k] = a
		return a
	}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, c := range a.ConnectLatency {
			k := key{c.Namespace, c.Pod, c.WorkloadKind, c.WorkloadName, a.Node}
			x := ensure(k)
			x.connectEstablished += c.Established
			x.connectTotalUS += c.TotalLatencyUS
			if c.MaxLatencyUS > x.connectMaxUS {
				x.connectMaxUS = c.MaxLatencyUS
			}
		}
		for _, t := range a.TCPHealth {
			k := key{t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName, a.Node}
			x := ensure(k)
			x.retrans += t.Retransmissions
			x.rtos += t.RTOs
		}
		for _, d := range a.DNSHealth {
			k := key{d.Namespace, d.Pod, d.WorkloadKind, d.WorkloadName, a.Node}
			x := ensure(k)
			x.dnsFail += d.Failures
			x.dnsQ += d.Queries
		}
	}
	out := Result{
		Workloads: []WorkloadScore{},
		Note:      "Workload digital experience from connect latency, TCP retrans/RTO, and DNS failures. SLO breach: avg connect >200ms, DNS fail ≥10%, or RTOs >10.",
	}
	for k, x := range by {
		if k.ns == "" && k.pod == "" && k.name == "" {
			continue
		}
		ws := WorkloadScore{
			Namespace: k.ns, Pod: k.pod, WorkloadKind: k.kind, WorkloadName: k.name, Node: k.node,
			Retransmits: x.retrans, RTOs: x.rtos, DNSFailures: x.dnsFail, DNSQueries: x.dnsQ,
			MaxConnectUS: x.connectMaxUS,
		}
		if x.connectEstablished > 0 {
			ws.AvgConnectUS = x.connectTotalUS / x.connectEstablished
		}
		ws.Score, ws.Severity, ws.Signals = score(ws)
		ws.SLOBreached = ws.AvgConnectUS > 200_000 || (ws.DNSQueries > 10 && ws.DNSFailures*10 >= ws.DNSQueries) || ws.RTOs > 10
		if ws.SLOBreached {
			ws.Signals = append(ws.Signals, "slo-breach")
			out.SLOBreaches++
		}
		out.Workloads = append(out.Workloads, ws)
		if ws.Severity == "high" || ws.Severity == "critical" {
			out.Degraded++
		}
	}
	sort.Slice(out.Workloads, func(i, j int) bool {
		if out.Workloads[i].Score != out.Workloads[j].Score {
			return out.Workloads[i].Score < out.Workloads[j].Score // worst first
		}
		return strings.Compare(out.Workloads[i].Namespace+out.Workloads[i].Pod, out.Workloads[j].Namespace+out.Workloads[j].Pod) < 0
	})
	if len(out.Workloads) > limit {
		out.Workloads = out.Workloads[:limit]
		out.Capped = true
	}
	out.Count = len(out.Workloads)
	return out
}

func score(w WorkloadScore) (int, string, []string) {
	s := 100
	var signals []string
	// Connect latency: >100ms avg hurts, >500ms hurts more.
	if w.AvgConnectUS > 500_000 {
		s -= 35
		signals = append(signals, "high-avg-connect-latency")
	} else if w.AvgConnectUS > 100_000 {
		s -= 15
		signals = append(signals, "elevated-avg-connect-latency")
	}
	if w.MaxConnectUS > 2_000_000 {
		s -= 15
		signals = append(signals, "high-max-connect-latency")
	}
	if w.Retransmits > 100 {
		s -= 25
		signals = append(signals, "high-retransmissions")
	} else if w.Retransmits > 10 {
		s -= 10
		signals = append(signals, "retransmissions")
	}
	if w.RTOs > 20 {
		s -= 20
		signals = append(signals, "tcp-rto")
	} else if w.RTOs > 0 {
		s -= 5
		signals = append(signals, "tcp-rto-seen")
	}
	if w.DNSQueries > 0 {
		ratio := float64(w.DNSFailures) / float64(w.DNSQueries)
		if ratio >= 0.3 {
			s -= 25
			signals = append(signals, "high-dns-failure-ratio")
		} else if ratio >= 0.1 {
			s -= 10
			signals = append(signals, "dns-failures")
		}
	}
	if s < 0 {
		s = 0
	}
	sev := "low"
	if s < 80 {
		sev = "medium"
	}
	if s < 60 {
		sev = "high"
	}
	if s < 40 {
		sev = "critical"
	}
	if len(signals) == 0 {
		signals = []string{"healthy"}
	}
	return s, sev, signals
}
