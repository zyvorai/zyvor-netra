// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
)

func (s *Server) flowHistory(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseFlowQuery(w, r)
	if !ok {
		return
	}
	if p, ok := principalFrom(r.Context()); ok && !p.Unrestricted() {
		if q.Namespace != "" && !p.AllowsNamespace(q.Namespace) {
			s.metricsData.rbacDenied.Add(1)
			errorJSON(w, http.StatusForbidden, "scope does not allow this namespace")
			return
		}
		if len(p.Clusters) > 0 && !p.allowsDim(p.Clusters, localCluster()) {
			s.metricsData.rbacDenied.Add(1)
			errorJSON(w, http.StatusForbidden, "scope does not allow this cluster")
			return
		}
		if len(p.Tenants) > 0 && !p.allowsDim(p.Tenants, localTenant()) {
			s.metricsData.rbacDenied.Add(1)
			errorJSON(w, http.StatusForbidden, "scope does not allow this tenant")
			return
		}
	}
	writeJSON(w, 200, s.filterFlowResult(r, s.store.FlowQuery(q)))
}

// fleetFlowHistory fans out the same filters to NETRA_FLEET_PEERS.
func (s *Server) fleetFlowHistory(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseFlowQuery(w, r)
	if !ok {
		return
	}
	local := s.filterFlowResult(r, s.store.FlowQuery(q))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	peers := fleet.ParsePeers(os.Getenv("NETRA_FLEET_PEERS"))
	if p, ok := principalFrom(r.Context()); ok && !p.Unrestricted() {
		var allowed []fleet.Peer
		for _, peer := range peers {
			if len(p.Clusters) > 0 && !p.allowsDim(p.Clusters, peer.Name) {
				continue
			}
			if len(p.Tenants) > 0 && (peer.Tenant == "" || !p.allowsDim(p.Tenants, peer.Tenant)) {
				continue
			}
			allowed = append(allowed, peer)
		}
		peers = allowed
	}
	writeJSON(w, 200, fleet.AggregateFlows(ctx,
		strings.TrimSpace(os.Getenv("NETRA_CLUSTER_NAME")),
		local, q, peers, nil))
}

func (s *Server) filterFlowResult(r *http.Request, res flowlog.Result) flowlog.Result {
	p, ok := principalFrom(r.Context())
	if !ok || p.Unrestricted() || len(p.Namespaces) == 0 {
		return res
	}
	var out []flowlog.Record
	for _, rec := range res.Records {
		if p.AllowsNamespace(rec.Namespace) {
			out = append(out, rec)
		}
	}
	res.Records = out
	res.Matched = len(out)
	res.Truncated = false
	return res
}

func (s *Server) parseFlowQuery(w http.ResponseWriter, r *http.Request) (flowlog.Query, bool) {
	now := time.Now().UTC()
	retain := flowlog.DefaultRetain
	if s.store != nil {
		if d := s.store.FlowRetain(); d > 0 {
			retain = d
		}
	}
	since := now.Add(-time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= retain {
			since = now.Add(-d)
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t.UTC()
		} else {
			http.Error(w, "since must be a duration within retention or RFC3339", http.StatusBadRequest)
			return flowlog.Query{}, false
		}
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 2000 {
		limit = n
	}
	qv := r.URL.Query()
	return flowlog.Query{
		Since:       since,
		Node:        qv.Get("node"),
		Namespace:   qv.Get("namespace"),
		Pod:         qv.Get("pod"),
		Peer:        qv.Get("peer"),
		Protocol:    qv.Get("protocol"),
		AppProtocol: qv.Get("app"),
		Limit:       limit,
	}, true
}

func (s *Server) insightsRED(w http.ResponseWriter, r *http.Request) {
	window := 5 * time.Minute
	if v := r.URL.Query().Get("window"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > flowlog.DefaultRetain {
			http.Error(w, "window must be a duration up to 168h", http.StatusBadRequest)
			return
		}
		window = d
	}
	now := time.Now().UTC()
	hist := s.store.FlowQuery(flowlog.Query{Since: now.Add(-window), Limit: flowlog.DefaultMax})
	writeJSON(w, 200, flowlog.RED(hist.Records, s.store.AgentStatuses(now, s.agentStaleAfter), window))
}

func (s *Server) insightTraces(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	since := now.Add(-15 * time.Minute)
	if v := r.URL.Query().Get("since"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > flowlog.DefaultRetain {
			http.Error(w, "since must be a duration up to 168h", http.StatusBadRequest)
			return
		}
		since = now.Add(-d)
	}
	q := r.URL.Query()
	hist := s.store.FlowQuery(flowlog.Query{
		Since: since, Limit: 500,
		Namespace: q.Get("namespace"), Pod: q.Get("pod"),
	})
	var ips map[string]flowlog.PodIP
	if s.kube != nil {
		if pods, err := s.kube.ListPods(r.Context(), q.Get("namespace")); err == nil {
			ips = map[string]flowlog.PodIP{}
			for _, p := range pods {
				if p.PodIP != "" {
					ips[p.PodIP] = flowlog.PodIP{Namespace: p.Namespace, Name: p.Name}
				}
			}
		}
	}
	writeJSON(w, 200, flowlog.Traces(hist.Records, ips))
}

func (s *Server) insightProfiles(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	var samples []models.StackSample
	for _, a := range s.store.AgentStatuses(now, s.agentStaleAfter) {
		samples = append(samples, a.StackSamples...)
	}
	if len(samples) > 50 {
		samples = samples[:50]
	}
	if samples == nil {
		samples = []models.StackSample{}
	}
	writeJSON(w, 200, map[string]any{
		"samples": samples,
		"count":   len(samples),
		"limitations": []string{
			"Kernel stacks from /proc/<pid>/stack for the top CPU comms on the latest agent tick, plus wchan when the process is waiting. Not a continuous profile and not a user-space flame graph.",
			"User-space frames are not collected. No argv or cmdline.",
			"A PID is skipped when both the kernel stack and wchan are empty.",
		},
	})
}

func (s *Server) workloadEvents(w http.ResponseWriter, r *http.Request) {
	out := kube.WarningEvents{Events: []kube.WorkloadEvent{}, Limitations: kube.EventLimitations()}
	if s.kube == nil {
		writeJSON(w, 200, out)
		return
	}
	ev, err := s.kube.ListWarningEvents(r.Context(), r.URL.Query().Get("namespace"))
	if err != nil {
		out.Error = err.Error()
		writeJSON(w, 200, out)
		return
	}
	if pod := r.URL.Query().Get("pod"); pod != "" {
		filtered := make([]kube.WorkloadEvent, 0, len(ev))
		for _, e := range ev {
			if e.Pod == pod {
				filtered = append(filtered, e)
			}
		}
		ev = filtered
	}
	if ev == nil {
		ev = []kube.WorkloadEvent{}
	}
	out.Available = true
	out.Events = ev
	writeJSON(w, 200, out)
}

func (s *Server) kernelNotes(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	var notes []models.KernelNote
	for _, a := range s.store.AgentStatuses(now, s.agentStaleAfter) {
		for _, n := range a.KernelNotes {
			if n.Node == "" {
				n.Node = a.Node
			}
			notes = append(notes, n)
		}
	}
	if len(notes) > 100 {
		notes = notes[len(notes)-100:]
	}
	if notes == nil {
		notes = []models.KernelNote{}
	}
	writeJSON(w, 200, map[string]any{
		"notes": notes,
		"count": len(notes),
		"limitations": []string{
			"Kernel log lines about netdev, TCP, UDP, conntrack, and OOM only.",
			"The application journal and dmesg dumps of other subsystems are not collected.",
			"Lines that look like credentials are dropped.",
		},
	})
}
