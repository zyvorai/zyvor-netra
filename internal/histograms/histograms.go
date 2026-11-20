// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package histograms builds low-cardinality Prometheus-style histogram
// snapshots from existing Netra agent samples (TCP retransmits, SRTT,
// connect latency) plus host counters (listen overflows, softirq NET_RX).
//
// Histograms are observe-only and intentionally avoid new BPF maps in the
// TC/cgroup hot path. Softirq *latency* (entry→exit) is deferred to an
// optional separate program; this package only exposes NET_RX counters.
package histograms

import (
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// Default upper bounds for exp2-style buckets (inclusive). The final +Inf
// bucket is implied by CumulativeCounts having one more entry than Bounds.
var (
	RetransBounds   = []float64{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
	SRTTBoundsUS    = []float64{100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1e6}
	ConnectBoundsUS = []float64{100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1e6, 5e6}
)

// Snapshot is a Prometheus-compatible cumulative histogram for one series.
type Snapshot struct {
	Name             string    `json:"name"`
	Bounds           []float64 `json:"bounds"`           // finite le= bounds
	CumulativeCounts []uint64  `json:"cumulativeCounts"` // len = len(Bounds)+1 (+Inf)
	Sum              float64   `json:"sum"`
	Count            uint64    `json:"count"`
}

// HostCounters are node-level kernel counters that are not themselves
// histogram samples but pair with the network-health story.
type HostCounters struct {
	ListenOverflows uint64 `json:"listenOverflows"`
	ListenDrops     uint64 `json:"listenDrops"`
	SoftirqNETRX    uint64 `json:"softirqNetRx"`
}

// Report is the agent-side payload embedded in AgentReport.
type Report struct {
	TCPRetransmissions Snapshot     `json:"tcpRetransmissions"`
	TCPSRTTUS          Snapshot     `json:"tcpSrttUs"`
	TCPConnectUS       Snapshot     `json:"tcpConnectUs"`
	Host               HostCounters `json:"host"`
}

// Observe builds a cumulative histogram from sample values.
func Observe(name string, bounds []float64, samples []float64) Snapshot {
	b := append([]float64(nil), bounds...)
	sort.Float64s(b)
	counts := make([]uint64, len(b)+1)
	var sum float64
	for _, v := range samples {
		sum += v
		placed := false
		for i, le := range b {
			if v <= le {
				counts[i]++
				placed = true
				break
			}
		}
		if !placed {
			counts[len(b)]++
		}
	}
	// Convert to cumulative.
	for i := 1; i < len(counts); i++ {
		counts[i] += counts[i-1]
	}
	return Snapshot{
		Name:             name,
		Bounds:           b,
		CumulativeCounts: counts,
		Sum:              sum,
		Count:            uint64(len(samples)),
	}
}

// FromAgentSamples builds network histograms from the current report maps.
// Each TCP health row contributes one retransmit sample and one SRTT sample
// (when RTTSamples > 0). Each connect-latency row with Established > 0
// contributes its average latency as one sample.
func FromAgentSamples(tcp []models.TCPHealthStat, connect []models.ConnectLatencyStat, host HostCounters) Report {
	retrans := make([]float64, 0, len(tcp))
	srtt := make([]float64, 0, len(tcp))
	for _, t := range tcp {
		retrans = append(retrans, float64(t.Retransmissions))
		if t.RTTSamples > 0 {
			srtt = append(srtt, float64(t.SRTTUS))
		}
	}
	conn := make([]float64, 0, len(connect))
	for _, c := range connect {
		if c.Established == 0 {
			continue
		}
		conn = append(conn, float64(c.TotalLatencyUS)/float64(c.Established))
	}
	return Report{
		TCPRetransmissions: Observe("tcp_retransmissions", RetransBounds, retrans),
		TCPSRTTUS:          Observe("tcp_srtt_us", SRTTBoundsUS, srtt),
		TCPConnectUS:       Observe("tcp_connect_us", ConnectBoundsUS, conn),
		Host:               host,
	}
}

// Merge sums compatible snapshots (same name and bounds). Used by the
// controller to aggregate across nodes for /metrics.
func Merge(parts ...Snapshot) Snapshot {
	if len(parts) == 0 {
		return Snapshot{}
	}
	out := Snapshot{
		Name:             parts[0].Name,
		Bounds:           append([]float64(nil), parts[0].Bounds...),
		CumulativeCounts: make([]uint64, len(parts[0].CumulativeCounts)),
	}
	for _, p := range parts {
		if p.Name != out.Name || len(p.Bounds) != len(out.Bounds) || len(p.CumulativeCounts) != len(out.CumulativeCounts) {
			continue
		}
		out.Sum += p.Sum
		out.Count += p.Count
		for i := range out.CumulativeCounts {
			out.CumulativeCounts[i] += p.CumulativeCounts[i]
		}
	}
	return out
}
