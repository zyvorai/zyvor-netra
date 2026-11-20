// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package observability

import (
	"sort"
	"strconv"

	"github.com/zyvorai/netra/internal/models"
)

func Topology(agents []models.AgentStatus, limit int) []models.NetworkEdge {
	if limit <= 0 {
		limit = 100
	}
	type key struct{ node, ns, pod, kind, workload, dest, proto string }
	m := map[key]models.NetworkEdge{}
	for _, a := range agents {
		for _, st := range a.Stats {
			if st.Namespace == "" && st.Pod == "" {
				continue
			}
			dest := st.DestinationIP
			if st.Port != 0 {
				dest += ":" + strconv.Itoa(int(st.Port))
			}
			k := key{a.Node, st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, dest, st.Protocol}
			e := m[k]
			e.Node, e.Namespace, e.Pod, e.WorkloadKind, e.WorkloadName, e.Destination, e.Protocol = k.node, k.ns, k.pod, k.kind, k.workload, k.dest, k.proto
			e.Packets += st.Packets
			e.Bytes += st.Bytes
			e.Blocked += st.Blocked
			m[k] = e
		}
	}
	out := make([]models.NetworkEdge, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packets == out[j].Packets {
			return out[i].Destination < out[j].Destination
		}
		return out[i].Packets > out[j].Packets
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
