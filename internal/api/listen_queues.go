// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/listenq"
	"github.com/zyvorai/netra/internal/models"
)

// listenQueuesView is the cluster-wide picture of TCP accept-queue pressure:
// which listeners are close to refusing connections, and how many half-open
// connections wait on them (internal/listenq).
type listenQueuesView struct {
	// Nodes reports every fresh agent, so a node that is not sampling is visible
	// as such: silence from it is not evidence that no queue is filling.
	Nodes        []listenQueueNode `json:"nodes"`
	Reporting    int               `json:"nodesReporting"`
	NotReporting int               `json:"nodesNotReporting"`
	// Listeners, Full, Saturated and SynRecv are the current values summed over
	// reporting nodes; Buckets is the cumulative fill histogram summed likewise.
	Listeners int               `json:"listeners"`
	Full      int               `json:"full"`
	Saturated int               `json:"saturated"`
	SynRecv   uint64            `json:"synRecv"`
	Buckets   map[string]uint64 `json:"buckets,omitempty"`
	Top       []listenQueueTop  `json:"top,omitempty"`
}

type listenQueueNode struct {
	Node        string `json:"node"`
	Reporting   bool   `json:"reporting"`
	Unavailable string `json:"unavailable,omitempty"`
}

type listenQueueTop struct {
	Node string `json:"node"`
	models.ListenQueueEntry
}

func entryPct(e models.ListenQueueEntry) int {
	return listenq.Listener{Queue: e.Queue, Max: e.Max}.Pct()
}

// aggregateListenQueues merges the fresh agents' summaries.
func aggregateListenQueues(agents []models.AgentStatus, top int) listenQueuesView {
	v := listenQueuesView{Nodes: []listenQueueNode{}, Buckets: map[string]uint64{}}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := listenQueueNode{Node: a.Node}
		q := a.ListenQueues
		if q == nil || q.Unavailable != "" {
			v.NotReporting++
			if q != nil {
				n.Unavailable = q.Unavailable
			}
			v.Nodes = append(v.Nodes, n)
			continue
		}
		n.Reporting = true
		v.Reporting++
		v.Listeners += q.Listeners
		v.Full += q.Full
		v.Saturated += q.Saturated
		v.SynRecv += q.SynRecv
		for b, c := range q.Buckets {
			v.Buckets[b] += c
		}
		for _, e := range q.Top {
			v.Top = append(v.Top, listenQueueTop{Node: a.Node, ListenQueueEntry: e})
		}
		v.Nodes = append(v.Nodes, n)
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].Node < v.Nodes[j].Node })
	sort.Slice(v.Top, func(i, j int) bool {
		a, b := v.Top[i], v.Top[j]
		if pa, pb := entryPct(a.ListenQueueEntry), entryPct(b.ListenQueueEntry); pa != pb {
			return pa > pb
		}
		if a.Queue != b.Queue {
			return a.Queue > b.Queue
		}
		if a.PeakPct != b.PeakPct {
			return a.PeakPct > b.PeakPct
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Port < b.Port
	})
	if top > 0 && len(v.Top) > top {
		v.Top = v.Top[:top]
	}
	if len(v.Buckets) == 0 {
		v.Buckets = nil
	}
	return v
}

// listenQueues serves GET /api/v1/listen-queues?top=N&node=NAME.
func (s *Server) listenQueues(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, aggregateListenQueues(agents, top))
}

// writeListenQueueMetrics adds aggregate accept-queue gauges to /metrics:
// cluster sums with the histogram bin as the one label (six fixed values).
// Ports and addresses are not labels; they are in the API.
func writeListenQueueMetrics(w http.ResponseWriter, agents []models.AgentStatus) {
	v := aggregateListenQueues(agents, 0)
	metricGauge(w, "netra_listen_queue_nodes_reporting", "Fresh node agents sampling TCP accept-queue depth.", float64(v.Reporting))
	metricGauge(w, "netra_listen_queue_nodes_not_reporting", "Fresh node agents not sampling accept queues (disabled, older agent, or the sockets could not be read).", float64(v.NotReporting))
	if v.Reporting == 0 {
		return
	}
	metricGauge(w, "netra_listen_queue_listeners", "TCP listening sockets right now, summed across reporting nodes.", float64(v.Listeners))
	metricGauge(w, "netra_listen_queue_full_listeners", "Listeners whose accept queue is full right now, i.e. refusing new connections.", float64(v.Full))
	metricGauge(w, "netra_listen_queue_saturated_listeners", "Listeners at or above 80% of their accept-queue capacity right now (includes full ones).", float64(v.Saturated))
	metricGauge(w, "netra_listen_queue_syn_recv", "Half-open connections (SYN received, final ACK pending) across all listeners right now.", float64(v.SynRecv))
	fmt.Fprint(w, "# HELP netra_listen_queue_fill_samples Accept-queue fill histogram: (listener, sample) pairs per fill level since each agent started, summed across nodes. Idle listeners dominate \"empty\".\n# TYPE netra_listen_queue_fill_samples gauge\n")
	for _, b := range listenq.Buckets {
		fmt.Fprintf(w, "netra_listen_queue_fill_samples{bucket=\"%s\"} %d\n", b, v.Buckets[b])
	}
}
