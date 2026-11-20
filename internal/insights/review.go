// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

// PolicyBlastRadius checks whether sourceID's currently-observed
// dependency-graph edges actually cross each of plan.RemovedDestinations —
// the traffic-aware half of a policy review (internal/policy.AnalyzeChange
// already does the semantic diffing; this only asks "does removing this
// destination allowance look like it would break something live"). Named
// distinctly from this package's own BlastRadius (the multi-hop graph
// traversal behind GET /api/v1/insights/blast-radius) — a different
// question about a different shape of result, sharing only the name
// "blast radius" as a concept.
//
// CIDR/IP-form destinations (`toCIDR`/`toCIDRSet`, prefixed "cidr:" by
// AnalyzeChange's destinationSet) match cleanly against graph node IPs.
// FQDN-form destinations ("fqdn:"/"fqdn-pattern:", which Recommendations()
// itself frequently generates from observed SNI) and Cilium entities
// ("entity:") get an honest "could not correlate" note rather than a false
// "no traffic" — the graph is IP-keyed and Netra does not persist
// FQDN→IP history, so absence of a CIDR match there proves nothing about
// an FQDN rule.
func PolicyBlastRadius(plan policy.ChangePlan, sourceID string, graph models.DependencyGraph) []models.BlastRadiusItem {
	nodeByID := make(map[string]models.DependencyNode, len(graph.Nodes))
	for _, n := range graph.Nodes {
		nodeByID[n.ID] = n
	}

	out := make([]models.BlastRadiusItem, 0, len(plan.RemovedDestinations))
	for _, d := range plan.RemovedDestinations {
		kind, value := splitDestination(d)
		item := models.BlastRadiusItem{Destination: d, Kind: kind}
		if kind != "cidr" {
			item.Note = "could not correlate to live traffic — the dependency graph is IP-keyed and Netra does not persist FQDN→IP history; absence of a CIDR match proves nothing here"
			out = append(out, item)
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			item.Note = "could not parse this CIDR destination"
			out = append(out, item)
			continue
		}
		item.Correlated = true
		var packets, bytes uint64
		for _, e := range graph.Edges {
			if e.Source != sourceID {
				continue
			}
			tgt := nodeByID[e.Target]
			if tgt.IP == "" {
				continue
			}
			addr, err := netip.ParseAddr(tgt.IP)
			if err != nil || !prefix.Contains(addr) {
				continue
			}
			item.ActiveTraffic = true
			packets += e.Packets
			bytes += e.Bytes
		}
		if item.ActiveTraffic {
			item.Note = fmt.Sprintf("observed traffic to this destination in the current dependency graph (%d packets, %d bytes cumulative) — removing this allowance would likely break an active connection", packets, bytes)
		} else {
			item.Note = "no observed traffic to this destination in the current dependency graph — but absence here only means no traffic was observed in this graph's window, not that the destination is unused"
		}
		out = append(out, item)
	}
	return out
}

// splitDestination reverses AnalyzeChange's destinationSet prefixing
// ("fqdn:", "fqdn-pattern:", "cidr:", "entity:" — internal/policy/plan.go).
func splitDestination(d string) (kind, value string) {
	for _, k := range []string{"fqdn-pattern", "fqdn", "cidr", "entity"} {
		if v, ok := strings.CutPrefix(d, k+":"); ok {
			return k, v
		}
	}
	return "unknown", d
}
