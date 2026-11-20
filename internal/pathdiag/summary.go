// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package pathdiag

import (
	"fmt"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// Build summarizes exact sockops path-pressure and connect-latency maps.
// It intentionally reports kernel TCP transport signals, not arbitrary skb drop reasons.
func Build(agents []models.AgentStatus, topN int) models.PathDiagnosticsResponse {
	if topN <= 0 {
		topN = 50
	}
	out := models.PathDiagnosticsResponse{EdgeIntel: models.EdgeIntelSummary{Counts: map[string]uint64{}}}
	var connectLatencyTotal uint64
	for _, a := range agents {
		if a.Stale {
			continue
		}
		mergeEdgeIntel(&out.EdgeIntel, a.EdgeIntel)
		for _, p := range a.TCPPressure {
			out.Pressure = append(out.Pressure, p)
			out.Summary.PacketsOut += p.PacketsOut
			out.Summary.RetransOut += p.RetransOut
			out.Summary.LostOut += p.LostOut
			out.Summary.TotalRetrans += p.TotalRetrans
			if p.RateIntervalUS > 0 {
				out.Summary.DeliveredRatePPS += p.RateDelivered * 1_000_000 / p.RateIntervalUS
			}
			if p.PacketsOut > 0 || p.RetransOut > 0 || p.LostOut > 0 {
				out.Summary.PressureFlows++
			}
			if p.SendCWND > 0 && p.PacketsOut*100 >= p.SendCWND*80 {
				out.Summary.CongestedFlows++
			}
		}
		for _, c := range a.ConnectLatency {
			out.Connect = append(out.Connect, c)
			out.Summary.ConnectionsMeasured += c.Established
			connectLatencyTotal += c.TotalLatencyUS
			if c.MaxLatencyUS > out.Summary.MaxConnectUS {
				out.Summary.MaxConnectUS = c.MaxLatencyUS
			}
		}
	}
	if out.Summary.ConnectionsMeasured > 0 {
		out.Summary.AverageConnectUS = connectLatencyTotal / out.Summary.ConnectionsMeasured
	}
	out.Summary.Anomalies = anomalies(out.Pressure, out.Connect)
	sort.Slice(out.Pressure, func(i, j int) bool { return pressureScore(out.Pressure[i]) > pressureScore(out.Pressure[j]) })
	sort.Slice(out.Connect, func(i, j int) bool { return avgConnect(out.Connect[i]) > avgConnect(out.Connect[j]) })
	if len(out.Pressure) > topN {
		out.Pressure = out.Pressure[:topN]
	}
	if len(out.Connect) > topN {
		out.Connect = out.Connect[:topN]
	}
	return out
}

// mergeEdgeIntel sums one node's edge-TCP-intel report into the running
// cluster-wide total. src is nil for a node edge intel never attached on
// (NETRA_EDGE_INTEL=off, or auto-mode attach failure) — that node simply
// contributes nothing, same as a stale node being skipped by the caller.
func mergeEdgeIntel(dst *models.EdgeIntelSummary, src *models.EdgeIntelSummary) {
	if src == nil {
		return
	}
	mergeEdgeIntelBuckets(&dst.Handshake, src.Handshake)
	mergeEdgeIntelBuckets(&dst.RTT, src.RTT)
	for k, v := range src.Counts {
		dst.Counts[k] += v
	}
}

func mergeEdgeIntelBuckets(dst *[]models.EdgeIntelBucket, src []models.EdgeIntelBucket) {
	for i, b := range src {
		for len(*dst) <= i {
			*dst = append(*dst, models.EdgeIntelBucket{})
		}
		(*dst)[i].Count += b.Count
		(*dst)[i].TotalNS += b.TotalNS
		if b.MaxNS > (*dst)[i].MaxNS {
			(*dst)[i].MaxNS = b.MaxNS
		}
	}
}

func avgConnect(c models.ConnectLatencyStat) uint64 {
	if c.Established == 0 {
		return 0
	}
	return c.TotalLatencyUS / c.Established
}

func pressureScore(p models.TCPPressureStat) uint64 {
	score := p.LostOut*1_000_000 + p.RetransOut*100_000 + p.TotalRetrans*1_000
	if p.SendCWND > 0 {
		score += p.PacketsOut * 100 / p.SendCWND
	}
	return score
}

func label(ns, pod, remote string, port uint16) string {
	if ns != "" || pod != "" {
		return fmt.Sprintf("%s/%s → %s:%d", ns, pod, remote, port)
	}
	return fmt.Sprintf("%s:%d", remote, port)
}

func anomalies(pressure []models.TCPPressureStat, connect []models.ConnectLatencyStat) []models.NetworkHealthAnomaly {
	out := make([]models.NetworkHealthAnomaly, 0, 64)
	for _, p := range pressure {
		sub := label(p.Namespace, p.Pod, p.RemoteIP, p.RemotePort)
		if p.LostOut > 0 {
			sev := "warning"
			if p.LostOut >= 10 {
				sev = "critical"
			}
			out = append(out, models.NetworkHealthAnomaly{Severity: sev, Kind: "tcp-loss-outstanding", Subject: sub, Message: fmt.Sprintf("%d TCP segments currently marked lost by the kernel", p.LostOut), Value: float64(p.LostOut)})
		}
		if p.RetransOut > 0 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "tcp-retransmit-outstanding", Subject: sub, Message: fmt.Sprintf("%d retransmitted TCP segments are currently outstanding", p.RetransOut), Value: float64(p.RetransOut)})
		}
		if p.SendCWND > 0 && p.PacketsOut*100 >= p.SendCWND*90 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "cwnd-pressure", Subject: sub, Message: fmt.Sprintf("packets_out=%d is at least 90%% of snd_cwnd=%d", p.PacketsOut, p.SendCWND), Value: float64(p.PacketsOut) * 100 / float64(p.SendCWND)})
		}
		if p.TotalRetrans >= 50 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "tcp-total-retrans", Subject: sub, Message: fmt.Sprintf("kernel reports %d cumulative retransmitted segments for this socket", p.TotalRetrans), Value: float64(p.TotalRetrans)})
		}
	}
	for _, c := range connect {
		avg := avgConnect(c)
		sub := label(c.Namespace, c.Pod, c.RemoteIP, c.RemotePort)
		if c.MaxLatencyUS >= 1_000_000 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "critical", Kind: "connect-latency", Subject: sub, Message: fmt.Sprintf("maximum measured TCP connect establishment latency is %.1f ms", float64(c.MaxLatencyUS)/1000), Value: float64(c.MaxLatencyUS) / 1000})
		} else if avg >= 250_000 || c.MaxLatencyUS >= 500_000 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "connect-latency", Subject: sub, Message: fmt.Sprintf("average TCP connect establishment latency %.1f ms, max %.1f ms", float64(avg)/1000, float64(c.MaxLatencyUS)/1000), Value: float64(avg) / 1000})
		}
	}
	order := map[string]int{"critical": 3, "warning": 2, "info": 1}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Severity] != order[out[j].Severity] {
			return order[out[i].Severity] > order[out[j].Severity]
		}
		return out[i].Value > out[j].Value
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}
