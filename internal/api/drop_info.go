// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// dropInfoView is the cluster-wide picture from the nodes' drop attribution
// (bpf/netra_dropinfo.c): which connections the kernel is dropping, why, and
// which kernel function dropped them.
type dropInfoView struct {
	// Nodes reports every fresh agent, so a node without the sensor is visible
	// as such: silence from it is not evidence that nothing is being dropped.
	Nodes        []dropInfoNode        `json:"nodes"`
	Reporting    int                   `json:"nodesReporting"`
	NotReporting int                   `json:"nodesNotReporting"`
	Totals       models.DropInfoTotals `json:"totals"`
	Reasons      []dropReasonCount     `json:"reasons,omitempty"`
	Sites        []models.DropInfoSite `json:"sites,omitempty"`
	Flows        []dropInfoFlow        `json:"flows,omitempty"`
}

type dropInfoNode struct {
	Node      string `json:"node"`
	Reporting bool   `json:"reporting"`
	// Unavailable is why a node that tried is not reporting (e.g. no kernel
	// BTF). Empty for a node that is off or runs an older agent.
	Unavailable string `json:"unavailable,omitempty"`
}

type dropReasonCount struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

type dropInfoFlow struct {
	Node string `json:"node"`
	models.DropInfoFlow
}

// aggregateDropInfo merges the fresh agents' summaries. Counts are cumulative
// since each agent's sensor attached, so sums are since-attach, per node.
// reason, when non-empty, restricts Sites and Flows (not Totals or Reasons) to
// that drop reason.
func aggregateDropInfo(agents []models.AgentStatus, top int, reason string) dropInfoView {
	v := dropInfoView{Nodes: []dropInfoNode{}}
	reasons := map[string]uint64{}
	sites := map[[2]string]uint64{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := dropInfoNode{Node: a.Node}
		d := a.DropInfo
		if d == nil || !d.Attached {
			v.NotReporting++
			if d != nil {
				n.Unavailable = d.Unavailable
			}
			v.Nodes = append(v.Nodes, n)
			continue
		}
		n.Reporting = true
		v.Reporting++
		v.Totals.Drops += d.Totals.Drops
		v.Totals.WithTuple += d.Totals.WithTuple
		v.Totals.NoTuple += d.Totals.NoTuple
		v.Totals.NoHeader += d.Totals.NoHeader
		v.Totals.ReadErrors += d.Totals.ReadErrors
		v.Totals.MapFull += d.Totals.MapFull
		for r, c := range d.Reasons {
			reasons[r] += c
		}
		for _, s := range d.Sites {
			if reason == "" || s.Reason == reason {
				sites[[2]string{s.Reason, s.Location}] += s.Count
			}
		}
		for _, f := range d.Flows {
			if reason == "" || f.Reason == reason {
				v.Flows = append(v.Flows, dropInfoFlow{Node: a.Node, DropInfoFlow: f})
			}
		}
		v.Nodes = append(v.Nodes, n)
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].Node < v.Nodes[j].Node })
	for r, c := range reasons {
		v.Reasons = append(v.Reasons, dropReasonCount{Reason: r, Count: c})
	}
	sort.Slice(v.Reasons, func(i, j int) bool {
		if v.Reasons[i].Count != v.Reasons[j].Count {
			return v.Reasons[i].Count > v.Reasons[j].Count
		}
		return v.Reasons[i].Reason < v.Reasons[j].Reason
	})
	for k, c := range sites {
		v.Sites = append(v.Sites, models.DropInfoSite{Reason: k[0], Location: k[1], Count: c})
	}
	sort.Slice(v.Sites, func(i, j int) bool {
		a, b := v.Sites[i], v.Sites[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Location < b.Location
	})
	sort.Slice(v.Flows, func(i, j int) bool {
		a, b := v.Flows[i], v.Flows[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.LastSeenNS > b.LastSeenNS
	})
	if top > 0 {
		if len(v.Flows) > top {
			v.Flows = v.Flows[:top]
		}
		if len(v.Sites) > top {
			v.Sites = v.Sites[:top]
		}
	}
	return v
}

// ebpfDropInfo serves GET /api/v1/ebpf/drop-info?top=N&node=NAME&reason=NAME.
func (s *Server) ebpfDropInfo(w http.ResponseWriter, r *http.Request) {
	top := 20
	if n, err := strconv.Atoi(r.URL.Query().Get("top")); err == nil && n > 0 {
		top = min(n, 500)
	}
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	if node := r.URL.Query().Get("node"); node != "" {
		kept := agents[:0:0]
		for _, a := range agents {
			if a.Node == node {
				kept = append(kept, a)
			}
		}
		agents = kept
	}
	writeJSON(w, http.StatusOK, aggregateDropInfo(agents, top, r.URL.Query().Get("reason")))
}

// maxDropReasonSeries bounds netra_drop_info_reason_drops; a kernel defines
// about a hundred reasons and a handful ever occur, the rest fold into "other".
const maxDropReasonSeries = 30

// writeDropInfoMetrics adds aggregate drop gauges to /metrics: cluster sums,
// with the reason as the one label (bounded). Tuples and kernel functions are
// deliberately not labels; they are in the API.
func writeDropInfoMetrics(w http.ResponseWriter, agents []models.AgentStatus) {
	v := aggregateDropInfo(agents, 0, "")
	metricGauge(w, "netra_drop_info_nodes_reporting", "Fresh node agents whose kernel drop attribution is running.", float64(v.Reporting))
	metricGauge(w, "netra_drop_info_nodes_not_reporting", "Fresh node agents without drop attribution (no kernel BTF, tracefs not readable, or disabled).", float64(v.NotReporting))
	if v.Reporting == 0 {
		return
	}
	metricGauge(w, "netra_drop_info_drops", "Packets the kernel dropped (skb:kfree_skb), summed across reporting nodes since each attached.", float64(v.Totals.Drops))
	metricGauge(w, "netra_drop_info_drops_without_tuple", "Dropped packets with no readable IP header (not IP, or dropped before it was parsed).", float64(v.Totals.NoTuple+v.Totals.NoHeader))
	metricGauge(w, "netra_drop_info_read_errors", "Drop records the kernel program could not read. Non-zero means the counts are an undercount.", float64(v.Totals.ReadErrors))
	if len(v.Reasons) > 0 {
		fmt.Fprint(w, "# HELP netra_drop_info_reason_drops Kernel packet drops by reason (names from the running kernel), summed across reporting nodes.\n# TYPE netra_drop_info_reason_drops gauge\n")
		var other uint64
		for i, rc := range v.Reasons {
			if i >= maxDropReasonSeries {
				other += rc.Count
				continue
			}
			fmt.Fprintf(w, "netra_drop_info_reason_drops{reason=\"%s\"} %d\n", promLabel(rc.Reason), rc.Count)
		}
		if other > 0 {
			fmt.Fprintf(w, "netra_drop_info_reason_drops{reason=\"other\"} %d\n", other)
		}
	}
}
