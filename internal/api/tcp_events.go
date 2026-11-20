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

// tcpEventsView is the cluster-wide picture from the nodes' TCP event
// tracepoints (bpf/netra_tcpevents.c).
type tcpEventsView struct {
	// Nodes reports every fresh agent, so a node without the sensor is visible
	// as such: silence from it is not evidence of a healthy network.
	Nodes        []tcpEventsNode             `json:"nodes"`
	Reporting    int                         `json:"nodesReporting"`
	NotReporting int                         `json:"nodesNotReporting"`
	Totals       models.TCPEventTotals       `json:"totals"`
	Transitions  []models.TCPStateTransition `json:"transitions,omitempty"`
	Flows        []tcpEventsFlow             `json:"flows,omitempty"`
}

type tcpEventsNode struct {
	Node      string            `json:"node"`
	Sensors   []string          `json:"sensors"`
	Skipped   map[string]string `json:"skipped,omitempty"`
	Reporting bool              `json:"reporting"`
}

type tcpEventsFlow struct {
	Node string `json:"node"`
	models.TCPEventFlow
}

// aggregateTCPEvents merges the fresh agents' summaries. Counts are cumulative
// since each agent's sensor attached, so sums are since-attach, per node.
func aggregateTCPEvents(agents []models.AgentStatus, topFlows int) tcpEventsView {
	v := tcpEventsView{Nodes: []tcpEventsNode{}}
	trans := map[[2]string]uint64{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := tcpEventsNode{Node: a.Node, Sensors: []string{}}
		te := a.TCPEvents
		if te != nil && len(te.Attached) > 0 {
			n.Reporting = true
			n.Sensors = te.Attached
			n.Skipped = te.Skipped
			v.Reporting++
			v.Totals.Retransmits += te.Totals.Retransmits
			v.Totals.RSTSent += te.Totals.RSTSent
			v.Totals.RSTReceived += te.Totals.RSTReceived
			v.Totals.StateTransitions += te.Totals.StateTransitions
			v.Totals.ReadErrors += te.Totals.ReadErrors
			v.Totals.BadFamily += te.Totals.BadFamily
			v.Totals.MapFull += te.Totals.MapFull
			for _, t := range te.Transitions {
				trans[[2]string{t.From, t.To}] += t.Count
			}
			for _, f := range te.Flows {
				v.Flows = append(v.Flows, tcpEventsFlow{Node: a.Node, TCPEventFlow: f})
			}
		} else {
			v.NotReporting++
			if te != nil {
				n.Skipped = te.Skipped
			}
		}
		v.Nodes = append(v.Nodes, n)
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].Node < v.Nodes[j].Node })
	for k, c := range trans {
		v.Transitions = append(v.Transitions, models.TCPStateTransition{From: k[0], To: k[1], Count: c})
	}
	sort.Slice(v.Transitions, func(i, j int) bool {
		if v.Transitions[i].Count != v.Transitions[j].Count {
			return v.Transitions[i].Count > v.Transitions[j].Count
		}
		return v.Transitions[i].From+v.Transitions[i].To < v.Transitions[j].From+v.Transitions[j].To
	})
	sort.Slice(v.Flows, func(i, j int) bool {
		a, b := v.Flows[i], v.Flows[j]
		ta, tb := a.Retransmits+a.RSTSent+a.RSTReceived, b.Retransmits+b.RSTSent+b.RSTReceived
		if ta != tb {
			return ta > tb
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.LastSeenNS > b.LastSeenNS
	})
	if topFlows > 0 && len(v.Flows) > topFlows {
		v.Flows = v.Flows[:topFlows]
	}
	return v
}

// ebpfTCPEvents serves GET /api/v1/ebpf/tcp-events?top=N&node=NAME.
func (s *Server) ebpfTCPEvents(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, aggregateTCPEvents(agents, top))
}

// writeTCPEventMetrics adds aggregate TCP event gauges to /metrics: cluster
// sums only, with the transition matrix as its one labelled family (at most
// 13x13 series). No per-flow or per-workload labels.
func writeTCPEventMetrics(w http.ResponseWriter, agents []models.AgentStatus) {
	v := aggregateTCPEvents(agents, 0)
	metricGauge(w, "netra_tcp_events_nodes_reporting", "Fresh node agents whose TCP event tracepoints are running.", float64(v.Reporting))
	metricGauge(w, "netra_tcp_events_nodes_not_reporting", "Fresh node agents without TCP event tracepoints (a missing tracepoint, unexpected record layout, or disabled).", float64(v.NotReporting))
	if v.Reporting == 0 {
		return
	}
	metricGauge(w, "netra_tcp_events_retransmits", "TCP retransmit events counted by the kernel tracepoint, summed across reporting nodes since each attached.", float64(v.Totals.Retransmits))
	metricGauge(w, "netra_tcp_events_rst_sent", "TCP RSTs sent by sockets, from tcp_send_reset. RSTs the kernel sends for a port with no socket are not reported by that tracepoint.", float64(v.Totals.RSTSent))
	metricGauge(w, "netra_tcp_events_rst_received", "TCP RSTs received by sockets, from tcp_receive_reset.", float64(v.Totals.RSTReceived))
	metricGauge(w, "netra_tcp_events_read_errors", "TCP event records the kernel program could not read. Non-zero means the counts above are an undercount.", float64(v.Totals.ReadErrors))
	if len(v.Transitions) > 0 {
		fmt.Fprint(w, "# HELP netra_tcp_state_transitions TCP socket state transitions counted by sock:inet_sock_set_state, summed across reporting nodes.\n# TYPE netra_tcp_state_transitions gauge\n")
		for _, t := range v.Transitions {
			fmt.Fprintf(w, "netra_tcp_state_transitions{from=\"%s\",to=\"%s\"} %d\n", promLabel(t.From), promLabel(t.To), t.Count)
		}
	}
}
