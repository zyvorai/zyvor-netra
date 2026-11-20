// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dropdiag

import (
	"fmt"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// Build aggregates node-level kernel skb drop reasons with Linux softnet and
// interface counters. Kernel kfree_skb reasons are intentionally node-level:
// that tracepoint does not carry a trustworthy Kubernetes cgroup identity.
func Build(agents []models.AgentStatus, topN int) models.DropDiagnosticsResponse {
	if topN <= 0 {
		topN = 50
	}
	out := models.DropDiagnosticsResponse{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := models.NodeDropDiagnostics{Node: a.Node, Stack: a.Stack, KernelDrops: append([]models.KernelDropStat(nil), a.KernelDrops...), QdiscStats: append([]models.QdiscStat(nil), a.QdiscStats...)}
		sort.Slice(n.KernelDrops, func(i, j int) bool { return n.KernelDrops[i].Count > n.KernelDrops[j].Count })
		if len(n.KernelDrops) > topN {
			n.KernelDrops = n.KernelDrops[:topN]
		}
		out.Nodes = append(out.Nodes, n)
		for _, d := range a.KernelDrops {
			out.Summary.KernelDropEvents += d.Count
		}
		for _, q := range a.QdiscStats {
			out.Summary.QdiscDrops += q.Drops
		}
		out.Summary.SoftnetProcessed += a.Stack.SoftnetProcessed
		out.Summary.SoftnetDropped += a.Stack.SoftnetDropped
		out.Summary.SoftnetTimeSqueeze += a.Stack.SoftnetTimeSqueeze
		for _, it := range a.Stack.Interfaces {
			out.Summary.RXDropped += it.RXDropped
			out.Summary.TXDropped += it.TXDropped
			out.Summary.RXErrors += it.RXErrors
			out.Summary.TXErrors += it.TXErrors
			out.Summary.RXMissed += it.RXMissed
			out.Summary.RXNoHandler += it.RXNoHandler
		}
	}
	out.Summary.Anomalies = anomalies(out)
	sort.Slice(out.Nodes, func(i, j int) bool { return nodeScore(out.Nodes[i]) > nodeScore(out.Nodes[j]) })
	return out
}

func nodeScore(n models.NodeDropDiagnostics) uint64 {
	var x uint64
	for _, d := range n.KernelDrops {
		x += d.Count
	}
	x += n.Stack.SoftnetDropped*100 + n.Stack.SoftnetTimeSqueeze*20
	for _, it := range n.Stack.Interfaces {
		x += (it.RXDropped + it.TXDropped + it.RXMissed) * 20
		x += (it.RXErrors + it.TXErrors + it.RXNoHandler) * 50
	}
	return x
}

func anomalies(r models.DropDiagnosticsResponse) []models.NetworkHealthAnomaly {
	out := make([]models.NetworkHealthAnomaly, 0, 64)
	for _, n := range r.Nodes {
		if n.Stack.SoftnetDropped > 0 {
			sev := "warning"
			if n.Stack.SoftnetDropped >= 1000 {
				sev = "critical"
			}
			out = append(out, models.NetworkHealthAnomaly{Severity: sev, Kind: "softnet-drop", Subject: n.Node, Message: fmt.Sprintf("Linux softnet reports %d packets dropped before protocol processing", n.Stack.SoftnetDropped), Value: float64(n.Stack.SoftnetDropped)})
		}
		if n.Stack.SoftnetTimeSqueeze > 0 {
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "softnet-time-squeeze", Subject: n.Node, Message: fmt.Sprintf("softnet processing hit its budget %d times", n.Stack.SoftnetTimeSqueeze), Value: float64(n.Stack.SoftnetTimeSqueeze)})
		}
		for _, it := range n.Stack.Interfaces {
			drops := it.RXDropped + it.TXDropped + it.RXMissed
			errs := it.RXErrors + it.TXErrors + it.RXNoHandler
			if drops > 0 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "interface-drop", Subject: n.Node + "/" + it.Name, Message: fmt.Sprintf("interface counters report %d drops/missed packets", drops), Value: float64(drops)})
			}
			if errs > 0 {
				out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "interface-error", Subject: n.Node + "/" + it.Name, Message: fmt.Sprintf("interface counters report %d receive/transmit/no-handler errors", errs), Value: float64(errs)})
			}
		}
		for _, q := range n.QdiscStats {
			if q.Drops == 0 {
				continue
			}
			out = append(out, models.NetworkHealthAnomaly{Severity: "warning", Kind: "qdisc-drop", Subject: n.Node + "/" + q.Interface + "/" + q.Kind, Message: fmt.Sprintf("qdisc %s on %s reports %d drops", q.Kind, q.Interface, q.Drops), Value: float64(q.Drops)})
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
