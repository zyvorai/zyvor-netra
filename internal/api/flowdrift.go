// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/flowdrift"
	"github.com/zyvorai/netra/internal/flowlog"
)

// flowReadScopeOK applies the same namespace, cluster and tenant checks as
// the flow history export to a request that spans the whole flow history.
func (s *Server) flowReadScopeOK(w http.ResponseWriter, r *http.Request, namespace string) bool {
	p, ok := principalFrom(r.Context())
	if !ok || p.Unrestricted() {
		return true
	}
	deny := func(msg string) bool {
		s.metricsData.rbacDenied.Add(1)
		errorJSON(w, http.StatusForbidden, msg)
		return false
	}
	if namespace != "" && !p.AllowsNamespace(namespace) {
		return deny("scope does not allow this namespace")
	}
	if len(p.Clusters) > 0 && !p.allowsDim(p.Clusters, localCluster()) {
		return deny("scope does not allow this cluster")
	}
	if len(p.Tenants) > 0 && !p.allowsDim(p.Tenants, localTenant()) {
		return deny("scope does not allow this tenant")
	}
	return true
}

// driftWindow parses a duration query parameter within [lo, hi].
func driftWindow(w http.ResponseWriter, r *http.Request, name string, def, lo, hi time.Duration) (time.Duration, bool) {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return def, true
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < lo || d > hi {
		errorJSON(w, http.StatusBadRequest, name+" must be a duration from "+lo.String()+" to "+hi.String())
		return 0, false
	}
	return d, true
}

// driftInputs reads the flow history for a drift or shift request. The
// baseline is clamped to the configured retention so a long default does not
// pretend to have history the controller does not keep.
func (s *Server) driftInputs(w http.ResponseWriter, r *http.Request) (recs []flowlog.Record, o flowdrift.Options, ok bool) {
	q := r.URL.Query()
	ns := strings.TrimSpace(q.Get("namespace"))
	if !s.flowReadScopeOK(w, r, ns) {
		return
	}
	recent, ok1 := driftWindow(w, r, "recent", flowdrift.DefaultRecent, flowdrift.MinRecent, flowdrift.MaxRecent)
	if !ok1 {
		return
	}
	retain := flowlog.DefaultRetain
	if d := s.store.FlowRetain(); d > 0 {
		retain = d
	}
	maxBase := flowdrift.MaxBaseline
	if retain < maxBase {
		maxBase = retain
	}
	defBase := flowdrift.DefaultBaseline
	if defBase > maxBase {
		defBase = maxBase
	}
	base, ok2 := driftWindow(w, r, "baseline", defBase, time.Hour, maxBase)
	if !ok2 {
		return
	}
	minBase, ok3 := driftWindow(w, r, "min_baseline", flowdrift.DefaultMinBaseline, time.Minute, maxBase)
	if !ok3 {
		return
	}
	limit := parseExportLimit(r, flowdrift.DefaultLimit, flowdrift.MaxLimit)
	now := time.Now().UTC()
	res := s.filterFlowResult(r, s.store.FlowQuery(flowlog.Query{
		Since: now.Add(-recent - base), Node: strings.TrimSpace(q.Get("node")), Namespace: ns, Limit: flowlog.DefaultMax,
	}))
	o = flowdrift.Options{Now: now, Recent: recent, Baseline: base, MinBaseline: minBase, Limit: limit,
		PublicOnly: q.Get("public_only") == "true", Truncated: res.Truncated}
	return res.Records, o, true
}

// dependencyDrift serves GET /api/v1/insights/dependency-drift: workload
// dependencies that are new in the recent window (or have gone quiet)
// relative to the retained flow history. Read-only.
func (s *Server) dependencyDrift(w http.ResponseWriter, r *http.Request) {
	recs, o, ok := s.driftInputs(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, flowdrift.BuildDrift(recs, o))
}

// volumeShift serves GET /api/v1/insights/volume-shift: workloads whose byte
// rate moved by a factor against their own baseline. Read-only.
func (s *Server) volumeShift(w http.ResponseWriter, r *http.Request) {
	recs, o, ok := s.driftInputs(w, r)
	if !ok {
		return
	}
	so := flowdrift.ShiftOptions{Options: o}
	if v := strings.TrimSpace(r.URL.Query().Get("factor")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 1.5 || f > flowdrift.MaxFactor {
			errorJSON(w, http.StatusBadRequest, "factor must be a number from 1.5 to 1000")
			return
		}
		so.Factor = f
	}
	if v := strings.TrimSpace(r.URL.Query().Get("min_bytes")); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			errorJSON(w, http.StatusBadRequest, "min_bytes must be a positive whole number")
			return
		}
		so.MinBytes = n
	}
	switch v := strings.TrimSpace(r.URL.Query().Get("baseline_mode")); v {
	case "", flowdrift.ModeAverage:
	case flowdrift.ModeSameTime:
		if o.Recent > 24*time.Hour {
			errorJSON(w, http.StatusBadRequest, "baseline_mode=same-time needs a recent window of at most 24h")
			return
		}
		so.Mode = v
	default:
		errorJSON(w, http.StatusBadRequest, "baseline_mode must be average or same-time")
		return
	}
	writeJSON(w, http.StatusOK, flowdrift.BuildShift(recs, so))
}
