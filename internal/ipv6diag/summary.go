// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package ipv6diag aggregates node-level IPv6 extension-header and
// fragmentation counters into anomaly-shaped findings. The underlying
// data (ext_headers/fragmented/nonfirst_fragment/more_fragments/
// chain_truncated per packet) was already computed by the eBPF IPv6
// walker to decide whether L4 parsing was safe; this package is the
// first place any of it is surfaced rather than discarded.
package ipv6diag

import (
	"fmt"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// minFragmentationSample avoids flagging a high fragmentation *rate* from
// a statistically meaningless handful of packets right after a node/agent
// restart, when counters are still warming up.
const minFragmentationSample = 1000

// chainTruncatedThreshold is the count of chain-truncated walks (an
// IPv6 extension-header chain longer than the walker's bounded limit)
// above which it's worth flagging — a handful is expected from unusual
// but benign traffic; a sustained stream is worth an operator's attention.
const chainTruncatedThreshold = 100

// Build aggregates per-node IPv6 extension-header/fragmentation counters
// with anomaly detection. Node-level only: cgroup identity is not
// reliably available at all of the walker's call sites, so a consistent,
// comparable signal across nodes beats a partially-attributed one.
func Build(agents []models.AgentStatus, topN int) models.IPv6DiagnosticsResponse {
	if topN <= 0 {
		topN = 50
	}
	out := models.IPv6DiagnosticsResponse{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := models.NodeIPv6Diagnostics{Node: a.Node, ExtHeaders: append([]models.IPv6ExtHeaderStat(nil), a.IPv6ExtHeaders...)}
		sort.Slice(n.ExtHeaders, func(i, j int) bool { return n.ExtHeaders[i].Packets > n.ExtHeaders[j].Packets })
		if len(n.ExtHeaders) > topN {
			n.ExtHeaders = n.ExtHeaders[:topN]
		}
		out.Nodes = append(out.Nodes, n)
		for _, s := range a.IPv6ExtHeaders {
			out.Summary.Packets += s.Packets
			out.Summary.ExtHeaderPackets += s.ExtHeaderPackets
			out.Summary.Fragmented += s.Fragmented
			out.Summary.NonFirstFragments += s.NonFirstFragments
			out.Summary.ChainTruncated += s.ChainTruncated
		}
	}
	out.Summary.Anomalies = anomalies(out.Nodes)
	sort.Slice(out.Nodes, func(i, j int) bool { return nodeScore(out.Nodes[i]) > nodeScore(out.Nodes[j]) })
	return out
}

func nodeScore(n models.NodeIPv6Diagnostics) uint64 {
	var x uint64
	for _, s := range n.ExtHeaders {
		x += s.Fragmented*10 + s.ChainTruncated*20
	}
	return x
}

func anomalies(nodes []models.NodeIPv6Diagnostics) []models.NetworkHealthAnomaly {
	out := make([]models.NetworkHealthAnomaly, 0, 32)
	for _, n := range nodes {
		var packets, fragmented, chainTruncated uint64
		for _, s := range n.ExtHeaders {
			packets += s.Packets
			fragmented += s.Fragmented
			chainTruncated += s.ChainTruncated
		}
		if packets >= minFragmentationSample && fragmented > 0 {
			rate := float64(fragmented) / float64(packets)
			if rate >= 0.05 {
				sev := "warning"
				if rate >= 0.20 {
					sev = "critical"
				}
				out = append(out, models.NetworkHealthAnomaly{
					Severity: sev, Kind: "high-fragmentation-rate", Subject: n.Node,
					Message: fmt.Sprintf("%.1f%% of IPv6 packets observed are fragments (%d of %d)", rate*100, fragmented, packets),
					Value:   rate * 100,
				})
			}
		}
		if chainTruncated >= chainTruncatedThreshold {
			out = append(out, models.NetworkHealthAnomaly{
				Severity: "warning", Kind: "ext-chain-frequently-truncated", Subject: n.Node,
				Message: fmt.Sprintf("%d IPv6 packets exceeded the bounded extension-header walk; L4/L7 parsing was suppressed for them", chainTruncated),
				Value:   float64(chainTruncated),
			})
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
