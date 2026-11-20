// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import "github.com/zyvorai/netra/internal/models"

// attributePolicyDrops best-effort joins policy_drops rows to the PID/comm/
// workload identity already resolved for live TCP connections in tcp, by
// matching each egress TCP drop's local tuple against tcp's local tuple.
//
// This only ever attributes egress TCP drops: an ingress deny has no
// accepted local socket to attribute to (the SYN was rejected before one
// could exist), and UDP has no sockops-derived PID tracking at all. Those
// cases are returned with an explicit AttributionState rather than left
// silently blank, so a zero PID is never ambiguous between "we tried and
// missed" and "attribution is structurally impossible for this drop."
func (a *Agent) attributePolicyDrops(drops []models.PolicyDropStat, tcp []models.TCPHealthStat) []models.PolicyDropStat {
	if len(drops) == 0 {
		return drops
	}
	type tupleKey struct {
		family                string
		localIP, remoteIP     string
		localPort, remotePort uint16
	}
	byTuple := make(map[tupleKey]models.TCPHealthStat, len(tcp))
	for _, th := range tcp {
		if th.PID == 0 || th.OwnershipStale {
			continue
		}
		byTuple[tupleKey{th.Family, th.LocalIP, th.RemoteIP, th.LocalPort, th.RemotePort}] = th
	}

	const ipprotoTCP = 6
	const directionEgress = 0

	out := make([]models.PolicyDropStat, len(drops))
	for i, d := range drops {
		out[i] = d
		if d.Direction != directionEgress {
			out[i].AttributionState = "unattributable-ingress"
			continue
		}
		if d.Protocol != ipprotoTCP {
			out[i].AttributionState = "unattributable-protocol"
			continue
		}
		key := tupleKey{familyName(d.Family), d.SrcAddr, d.DstAddr, d.SrcPort, d.DstPort}
		th, ok := byTuple[key]
		if !ok {
			out[i].AttributionState = "unmatched"
			continue
		}
		out[i].PID, out[i].Comm, out[i].UID = th.PID, th.Comm, th.UID
		out[i].Namespace, out[i].Pod, out[i].WorkloadKind, out[i].WorkloadName = th.Namespace, th.Pod, th.WorkloadKind, th.WorkloadName
		out[i].AttributionState = "attributed"
	}
	return out
}
