// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package observability

import (
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// InterfaceSummary rolls up per-(interface, flow) counters into a
// per-node, per-interface view with top-N destinations. Only flows from
// Netra's TC/TCX-attached hooks contribute (see bpf/netra_tc.c's
// iface_flow_stats map comment) — this is a per-interface breakdown of
// that specific traffic, not the full cluster-wide flow picture already
// covered by Summarize.
func InterfaceSummary(agents []models.AgentStatus, topN int) models.InterfaceFlowResponse {
	if topN <= 0 {
		topN = 10
	}
	out := models.InterfaceFlowResponse{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		type accum struct {
			packets, bytes, blocked uint64
			dests                   map[string]uint64
		}
		byIface := map[string]*accum{}
		order := make([]string, 0, 4)
		for _, f := range a.InterfaceFlows {
			name := f.Interface
			if name == "" {
				name = utoa(uint64(f.IfIndex))
			}
			acc, ok := byIface[name]
			if !ok {
				acc = &accum{dests: map[string]uint64{}}
				byIface[name] = acc
				order = append(order, name)
			}
			acc.packets += f.Packets
			acc.bytes += f.Bytes
			acc.blocked += f.Blocked
			key := f.DestinationIP
			if f.DestinationPort != 0 {
				key += ":" + utoa(uint64(f.DestinationPort))
			}
			if key != "" {
				acc.dests[key] += f.Packets
			}
		}
		if len(order) == 0 {
			continue
		}
		sort.Strings(order)
		n := models.NodeInterfaceFlows{Node: a.Node}
		for _, name := range order {
			acc := byIface[name]
			n.Interfaces = append(n.Interfaces, models.InterfaceSummary{
				Interface: name, Packets: acc.packets, Bytes: acc.bytes, Blocked: acc.blocked,
				TopDests: top(acc.dests, topN),
			})
		}
		out.Nodes = append(out.Nodes, n)
	}
	return out
}
