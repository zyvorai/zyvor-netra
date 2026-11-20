// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// stackHistograms is GET /api/v1/ebpf/stack-histograms — observe-only
// softirq / softnet pressure and listen-queue depth buckets from current
// agent reports. Not entry→exit softirq latency (optional sensor not shipped).
func (s *Server) stackHistograms(w http.ResponseWriter, r *http.Request) {
	nodeFilter := r.URL.Query().Get("node")
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	type bucket struct {
		Label string `json:"label"`
		Count int    `json:"count"`
	}
	type nodeHist struct {
		Node               string                    `json:"node"`
		SoftirqNETRX       uint64                    `json:"softirqNetRx,omitempty"`
		SoftnetDropped     uint64                    `json:"softnetDropped,omitempty"`
		SoftnetTimeSqueeze uint64                    `json:"softnetTimeSqueeze,omitempty"`
		ListenDepthBuckets []bucket                  `json:"listenDepthBuckets"`
		ListenBuckets      map[string]uint64         `json:"listenFillBuckets,omitempty"`
		ListenOverflows    uint64                    `json:"listenOverflows,omitempty"`
		ListenDrops        uint64                    `json:"listenDrops,omitempty"`
		TopListeners       []models.ListenQueueEntry `json:"topListeners,omitempty"`
	}
	var nodes []nodeHist
	depthBuckets := []struct {
		label string
		max   int
	}{
		{"0", 0}, {"1-8", 8}, {"9-32", 32}, {"33-128", 128}, {"129+", 1 << 30},
	}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		if nodeFilter != "" && a.Node != nodeFilter {
			continue
		}
		nh := nodeHist{Node: a.Node, ListenDepthBuckets: make([]bucket, len(depthBuckets))}
		for i, b := range depthBuckets {
			nh.ListenDepthBuckets[i].Label = b.label
		}
		nh.SoftnetDropped = a.Stack.SoftnetDropped
		nh.SoftnetTimeSqueeze = a.Stack.SoftnetTimeSqueeze
		if a.Histograms != nil {
			nh.SoftirqNETRX = a.Histograms.Host.SoftirqNETRX
			nh.ListenOverflows = a.Histograms.Host.ListenOverflows
			nh.ListenDrops = a.Histograms.Host.ListenDrops
		}
		if a.ListenQueues != nil {
			nh.ListenBuckets = a.ListenQueues.Buckets
			entries := append([]models.ListenQueueEntry(nil), a.ListenQueues.Top...)
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Queue > entries[j].Queue
			})
			for _, e := range entries {
				depth := int(e.Queue)
				for i, b := range depthBuckets {
					if depth <= b.max {
						nh.ListenDepthBuckets[i].Count++
						break
					}
				}
			}
			if len(entries) > 10 {
				entries = entries[:10]
			}
			nh.TopListeners = entries
		}
		nodes = append(nodes, nh)
	}
	writeJSON(w, 200, map[string]any{
		"nodes": nodes,
		"note":  "Observe-only pressure buckets from agent reports. Softirq values are NET_RX counters, not entry→exit latency. Never changes tunables.",
		"limitations": []string{
			"Softirq latency histograms require an optional kprobe sensor not shipped here.",
			"Listen depth is a point-in-time inet_diag snapshot plus agent fill-level buckets.",
			"Netra never auto-applies backlog or softirq tunables.",
		},
	})
}
