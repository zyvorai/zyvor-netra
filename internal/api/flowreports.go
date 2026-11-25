// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/beacon"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/netpolcoverage"
)

// maxFlowWindow is the longest history window a report may ask for: its own
// bound, or the configured flow retention when that is shorter.
func (s *Server) maxFlowWindow(max time.Duration) time.Duration {
	retain := flowlog.DefaultRetain
	if d := s.store.FlowRetain(); d > 0 {
		retain = d
	}
	if retain < max {
		return retain
	}
	return max
}

// intParam parses a whole-number query parameter within [lo, hi].
func intParam(w http.ResponseWriter, r *http.Request, name string, def, lo, hi int) (int, bool) {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		errorJSON(w, http.StatusBadRequest, name+" must be a whole number from "+strconv.Itoa(lo)+" to "+strconv.Itoa(hi))
		return 0, false
	}
	return n, true
}

// securityBeacons serves GET /api/v1/security/beacons: pod-to-peer egress
// that repeats at a steady interval in the retained flow history. Read-only.
func (s *Server) securityBeacons(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ns := strings.TrimSpace(q.Get("namespace"))
	if !s.flowReadScopeOK(w, r, ns) {
		return
	}
	maxWin := s.maxFlowWindow(beacon.MaxWindow)
	window, ok := driftWindow(w, r, "window", min(beacon.DefaultWindow, maxWin), min(beacon.MinWindow, maxWin), maxWin)
	if !ok {
		return
	}
	minPeriod, ok := driftWindow(w, r, "min_period", beacon.DefaultMinPeriod, beacon.MinPeriodFloor, beacon.MaxMinPeriod)
	if !ok {
		return
	}
	minEvents, ok := intParam(w, r, "min_events", beacon.DefaultMinEvents, beacon.MinEventsFloor, beacon.MaxMinEvents)
	if !ok {
		return
	}
	limit, ok := intParam(w, r, "limit", beacon.DefaultLimit, 1, beacon.MaxLimit)
	if !ok {
		return
	}
	minScore := beacon.DefaultMinScore
	if v := strings.TrimSpace(q.Get("min_score")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		// The negated form also rejects NaN.
		if err != nil || !(f >= beacon.MinScoreFloor && f <= 1) {
			errorJSON(w, http.StatusBadRequest, "min_score must be a number from 0.5 to 1")
			return
		}
		minScore = f
	}
	now := time.Now().UTC()
	history := s.store.FlowQuery(flowlog.Query{
		Since: now.Add(-window), Node: strings.TrimSpace(q.Get("node")), Namespace: ns, Limit: flowlog.DefaultMax,
	})
	// Read before filtering: a cut history is still cut for a scoped caller.
	truncated := history.Truncated
	writeJSON(w, http.StatusOK, beacon.Build(s.filterFlowResult(r, history).Records, beacon.Options{
		Now: now, Window: window, MinEvents: minEvents, MinPeriod: minPeriod, MinScore: minScore,
		IncludePrivate: q.Get("include_private") == "true", Limit: limit, Truncated: truncated,
	}))
}

// netpolCoverage serves GET /api/v1/insights/netpol-coverage: which workloads
// no Kubernetes NetworkPolicy restricts, joined with the public traffic in the
// flow history. Read-only: it lists pods and policies and changes neither.
func (s *Server) netpolCoverage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ns := strings.TrimSpace(q.Get("namespace"))
	if !s.flowReadScopeOK(w, r, ns) {
		return
	}
	maxWin := s.maxFlowWindow(netpolcoverage.MaxWindow)
	window, ok := driftWindow(w, r, "window", min(netpolcoverage.DefaultWindow, maxWin), netpolcoverage.MinWindow, maxWin)
	if !ok {
		return
	}
	limit, ok := intParam(w, r, "limit", netpolcoverage.DefaultLimit, 1, netpolcoverage.MaxLimit)
	if !ok {
		return
	}
	if s.kube == nil {
		errorJSON(w, http.StatusServiceUnavailable, "Kubernetes client unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// A principal limited to namespaces lists only those, so nothing outside
	// its scope is read into the answer.
	namespaces := []string{ns}
	if p, ok := principalFrom(r.Context()); ok && ns == "" && len(p.Namespaces) > 0 {
		// An empty entry would mean "list the whole cluster": never pass it on.
		namespaces = nil
		for _, n := range p.Namespaces {
			if n = strings.TrimSpace(n); n != "" && !slices.Contains(namespaces, n) {
				namespaces = append(namespaces, n)
			}
		}
	}
	var pods []netpolcoverage.Pod
	var policies []netpolcoverage.Policy
	for _, n := range namespaces {
		rawPods, err := s.kube.ListActivePodItems(ctx, n)
		if err != nil {
			errorJSON(w, http.StatusBadGateway, err.Error())
			return
		}
		rawPolicies, err := s.kube.ListNetworkPolicyItems(ctx, n)
		if err != nil {
			errorJSON(w, http.StatusBadGateway, err.Error()+" (the controller's ClusterRole needs get and list on networking.k8s.io networkpolicies)")
			return
		}
		p, err := netpolcoverage.ParsePods(rawPods)
		if err != nil {
			errorJSON(w, http.StatusBadGateway, err.Error())
			return
		}
		np, err := netpolcoverage.ParsePolicies(rawPolicies)
		if err != nil {
			errorJSON(w, http.StatusBadGateway, err.Error())
			return
		}
		pods, policies = append(pods, p...), append(policies, np...)
	}
	now := time.Now().UTC()
	history := s.store.FlowQuery(flowlog.Query{Since: now.Add(-window), Namespace: ns, Limit: flowlog.DefaultMax})
	truncated := history.Truncated
	writeJSON(w, http.StatusOK, netpolcoverage.Build(pods, policies, s.filterFlowResult(r, history).Records, netpolcoverage.Options{
		Now: now, Window: window, All: q.Get("all") == "true", Limit: limit, Truncated: truncated,
	}))
}
