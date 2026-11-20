// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package observability

import (
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

func Summarize(agents []models.AgentStatus, topN int) models.EBPFObservabilitySummary {
	if topN <= 0 {
		topN = 10
	}
	s := models.EBPFObservabilitySummary{Protocols: map[string]uint64{}, Directions: map[string]uint64{}, Hooks: map[string]uint64{}}
	reasons, dns, procs, dests := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	workloads, blockedWorkloads := map[string]uint64{}, map[string]uint64{}
	for _, a := range agents {
		for _, st := range a.Stats {
			s.Packets += st.Packets
			s.Bytes += st.Bytes
			s.Blocked += st.Blocked
			if st.Protocol != "" {
				s.Protocols[st.Protocol] += st.Packets
			}
			if st.Direction != "" {
				s.Directions[st.Direction] += st.Packets
			}
			if st.Hook != "" {
				s.Hooks[st.Hook] += st.Packets
			}
			key := st.DestinationIP
			if st.Port != 0 {
				key += ":" + utoa(uint64(st.Port))
			}
			if key != "" {
				dests[key] += st.Packets
			}
			wk := workloadKey(st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName)
			if wk != "" {
				workloads[wk] += st.Packets
				blockedWorkloads[wk] += st.Blocked
			}
		}
		for _, e := range a.Events {
			s.Events++
			if e.Action == "blocked" {
				if e.Reason != "" {
					reasons[e.Reason]++
				}
			}
			if e.Type == "dns" && e.DNSQuery != "" {
				s.DNSQueries++
				dns[e.DNSQuery]++
			}
			if e.Type == "connect" || e.Hook == "socket" {
				s.SocketEvents++
			}
			if e.Comm != "" {
				procs[e.Comm]++
			}
		}
	}
	s.BlockReasons = top(reasons, topN)
	s.TopDNS = top(dns, topN)
	s.TopProcesses = top(procs, topN)
	s.TopDestinations = top(dests, topN)
	s.TopWorkloads = top(workloads, topN)
	s.TopBlockedWorkloads = topNonZero(blockedWorkloads, topN)
	return s
}

func top(m map[string]uint64, n int) []models.NamedCount {
	out := make([]models.NamedCount, 0, len(m))
	for k, v := range m {
		out = append(out, models.NamedCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func workloadKey(namespace, pod, kind, name string) string {
	if namespace == "" && pod == "" {
		return ""
	}
	key := namespace + "/" + pod
	if kind != "" || name != "" {
		key += " (" + kind + "/" + name + ")"
	}
	return key
}

func topNonZero(m map[string]uint64, n int) []models.NamedCount {
	clean := map[string]uint64{}
	for k, v := range m {
		if v > 0 {
			clean[k] = v
		}
	}
	return top(clean, n)
}
