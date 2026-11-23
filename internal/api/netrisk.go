// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/capacity"
	"github.com/zyvorai/netra/internal/denysim"
	"github.com/zyvorai/netra/internal/flooddetect"
	"github.com/zyvorai/netra/internal/flowexport"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/tlsposture"
	"github.com/zyvorai/netra/internal/tsdb"
)

// WithFloodTracker attaches the per-source rate tracker a cmd/netrad poller
// feeds. Optional: without it the flood endpoint still reports node-level
// vector findings and says per-source rates are unavailable.
func (s *Server) WithFloodTracker(t *flooddetect.Tracker) *Server {
	s.floodTracker = t
	return s
}

// windowParam parses a duration query parameter within [lo, hi].
func windowParam(r *http.Request, key string, def, lo, hi time.Duration) (time.Duration, string) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def, ""
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < lo || d > hi {
		return 0, fmt.Sprintf("%s must be a duration between %s and %s, e.g. %s", key, lo, hi, def)
	}
	return d, ""
}

// nodeSeries runs one grouped-by-node query and returns each node's values
// (NaN where the bucket had no sample).
func (s *Server) nodeSeries(ctx string, dims []string, nodes []string, window time.Duration, points int, group, aggregate string, now time.Time) (map[string][]float64, []int64, error) {
	res, err := tsdb.Run(s.metricsHub.Sources(), tsdb.Query{
		Context: ctx, Dimensions: dims, Nodes: nodes, After: -int64(window / time.Second), Points: points,
		Group: group, GroupBy: "node", Aggregate: aggregate,
	}, now)
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string][]float64, len(res.Dimensions))
	for _, d := range res.Dimensions {
		v := make([]float64, len(d.Values))
		for i, x := range d.Values {
			v[i] = float64(x)
		}
		out[d.Name] = v
	}
	return out, res.Timestamps, nil
}

type capacityResource struct {
	name, context, dim string
}

var capacityResources = []capacityResource{
	{"conntrack", "netfilter.conntrack_utilization", "used"},
	{"ephemeral-ports", "net.ephemeral_utilization", "used"},
}

// capacityForecast serves GET /api/v1/capacity/forecast?window=1h&node=GLOB.
// It forecasts conntrack-table and ephemeral-port exhaustion per node from
// the stored utilization series. Read-only.
func (s *Server) capacityForecast(w http.ResponseWriter, r *http.Request) {
	if !s.requireMetrics(w) {
		return
	}
	window, msg := windowParam(r, "window", time.Hour, 10*time.Minute, 24*time.Hour)
	if msg != "" {
		errorJSON(w, http.StatusBadRequest, msg)
		return
	}
	nodes := splitList(r.URL.Query().Get("node"))
	now := time.Now()
	points := int(window / (10 * time.Second))
	points = max(24, min(points, 360))
	var inputs []capacity.Input
	var gaps []string
	known := map[string]bool{}
	for _, src := range s.metricsHub.Sources() {
		if len(nodes) == 0 || tsdb.MatchAny(nodes, src.Node) {
			known[src.Node] = true
		}
	}
	for _, res := range capacityResources {
		series, ts, err := s.nodeSeries(res.context, []string{res.dim}, nodes, window, points, "max", "max", now)
		if err != nil {
			errorJSON(w, http.StatusInternalServerError, err.Error())
			return
		}
		seen := map[string]bool{}
		for node, vals := range series {
			seen[node] = true
			pts := make([]capacity.Point, 0, len(vals))
			for i, v := range vals {
				if i < len(ts) && !math.IsNaN(v) {
					pts = append(pts, capacity.Point{T: ts[i], V: v})
				}
			}
			inputs = append(inputs, capacity.Input{Node: node, Resource: res.name, Units: "%", Limit: 100, Points: pts})
		}
		for node := range known {
			if !seen[node] {
				gaps = append(gaps, fmt.Sprintf("no %s utilization series for node %s (collector not running, or an older agent)", res.name, node))
			}
		}
	}
	rep := capacity.Build(inputs, now)
	writeJSON(w, http.StatusOK, map[string]any{
		"generatedAt": rep.GeneratedAt, "window": window.String(), "forecasts": rep.Forecasts, "gaps": sortedStrings(gaps), "caveats": rep.Caveats,
	})
}

func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

type floodSpec struct {
	vector   flooddetect.Vector
	name     string
	context  string
	dims     []string
	floor    float64
	minRatio float64
}

// floodSpecs are the kernel counters read per node. Floors are events per
// second below which a rise is never reported.
var floodSpecs = []floodSpec{
	{flooddetect.VectorSYN, "SYN queue overflow (drops plus syncookies)", "ip.tcp_syn_queue", []string{"drops", "cookies"}, 1, 3},
	{flooddetect.VectorSYN, "passive TCP opens", "ipv4.tcpopens", []string{"passive"}, 500, 4},
	{flooddetect.VectorUDP, "UDP datagrams received", "ipv4.udppackets", []string{"received"}, 5000, 4},
	{flooddetect.VectorUDP, "UDP datagrams to closed ports", "ipv4.udperrors", []string{"NoPorts"}, 200, 4},
	{flooddetect.VectorICMP, "ICMP messages received", "ipv4.icmp", []string{"received"}, 500, 4},
	{flooddetect.VectorFragment, "IP fragments needing reassembly", "ipv4.fragments", []string{"reasm_reqds"}, 200, 4},
}

type floodSourceView struct {
	flooddetect.SourceFinding
	Lockout *denysim.Lockout `json:"lockout,omitempty"`
}

// floodFindings serves GET /api/v1/security/floods?window=30m. It reports
// inbound volumetric floods per node (against a robust baseline) and per
// source, with a suggested deny for public sources. It never applies a rule.
func (s *Server) floodFindings(w http.ResponseWriter, r *http.Request) {
	window, msg := windowParam(r, "window", 30*time.Minute, 10*time.Minute, 6*time.Hour)
	if msg != "" {
		errorJSON(w, http.StatusBadRequest, msg)
		return
	}
	now := time.Now()
	var node []flooddetect.NodeFinding
	gaps := []string{}
	evaluated := 0
	if s.metricsHub == nil {
		gaps = append(gaps, "per-second metrics are disabled (NETRA_METRICS_ENABLED): node-level vector detection is unavailable; only per-source rates are reported")
	} else {
		var signals []flooddetect.Signal
		for _, sp := range floodSpecs {
			series, _, err := s.nodeSeries(sp.context, sp.dims, nil, window, 120, "avg", "sum", now)
			if err != nil {
				errorJSON(w, http.StatusInternalServerError, err.Error())
				return
			}
			if len(series) == 0 {
				gaps = append(gaps, fmt.Sprintf("no data for %s (%s)", sp.name, sp.context))
			}
			for n, vals := range series {
				evaluated++
				signals = append(signals, flooddetect.Signal{Node: n, Vector: sp.vector, Name: sp.name, Floor: sp.floor, MinRatio: sp.minRatio, Values: vals})
			}
		}
		node = flooddetect.Analyze(signals)
	}
	var sources []floodSourceView
	warming := true
	if s.floodTracker == nil {
		gaps = append(gaps, "per-source flood tracking is not running on this controller")
	} else {
		warming = s.floodTracker.Warming(now)
		prot, perr := protectedDestinations()
		for _, f := range s.floodTracker.Findings(now) {
			v := floodSourceView{SourceFinding: f}
			if f.Suggestion != nil {
				p := denysim.Proposal{Kind: "ip", Value: f.Suggestion.Value, Direction: "ingress", Protocol: f.Suggestion.Protocol}
				if lo, err := denysim.CheckLockout(p, prot); err == nil {
					if perr != nil {
						lo.Caveat = "NETRA_PROTECTED_DESTINATIONS is invalid and was ignored (" + perr.Error() + "). " + lo.Caveat
					}
					v.Lockout = &lo
					if lo.Risk == denysim.RiskLikely {
						v.Suggestion = nil
						v.NoSuggestion = "a deny of this address would reach a protected path (see lockout); investigate instead"
					}
				}
			}
			sources = append(sources, v)
		}
	}
	if node == nil {
		node = []flooddetect.NodeFinding{}
	}
	if sources == nil {
		sources = []floodSourceView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generatedAt": now.UTC(), "window": window.String(), "nodeFindings": node, "sourceFindings": sources,
		"signalsEvaluated": evaluated, "sourcesWarming": warming, "gaps": gaps,
		"caveats": []string{
			"Detection and suggestion only. Nothing here applies a deny, changes the mode or touches a map: a suggested deny goes through POST /api/v1/ebpf/deny/preview, the self-lockout check and leased enforce, which fails open.",
			"Node findings compare the last ~45s with a robust median baseline of the window and need at least 20 clean baseline points; a flood already under way for the whole window becomes the baseline and is not flagged.",
			"Source rates come from the XDP shield's per-source counters (SYN attempts, shield-denied packets), so they need the shield loaded; source addresses of a volumetric attack are often spoofed.",
			"Only public unicast sources get a suggestion; private, loopback and link-local sources are workloads or nodes to investigate.",
		},
	})
}

// scopeAgentTLS drops fingerprints outside the principal's namespaces.
func scopeAgentTLS(r *http.Request, agents []models.AgentStatus) []models.AgentStatus {
	p, ok := principalFrom(r.Context())
	if !ok || p.Unrestricted() || len(p.Namespaces) == 0 {
		return agents
	}
	out := make([]models.AgentStatus, 0, len(agents))
	for _, a := range agents {
		keep := a.TLSFingerprints[:0:0]
		for _, fp := range a.TLSFingerprints {
			if p.AllowsNamespace(fp.Namespace) {
				keep = append(keep, fp)
			}
		}
		a.TLSFingerprints = keep
		out = append(out, a)
	}
	return out
}

// tlsPosture serves GET /api/v1/insights/tls-posture: client TLS versions
// offered per workload and SNI from JA4 metadata. No decryption.
func (s *Server) tlsPosture(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, tlsposture.Build(scopeAgentTLS(r, s.store.AgentStatuses(now, s.agentStaleAfter))))
}

// exportFlowSummary serves GET /api/v1/export/flow-summary: retained flow
// deltas as IPFIX-named summary records (json, jsonl or csv).
func (s *Server) exportFlowSummary(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "jsonl" && format != "csv" {
		errorJSON(w, http.StatusBadRequest, "format must be json, jsonl or csv")
		return
	}
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
	limit := parseExportLimit(r, flowexport.DefaultFlows, flowexport.MaxFlows)
	q.Limit = flowlog.DefaultMax
	res := s.filterFlowResult(r, s.store.FlowQuery(q))
	sum := flowexport.Build(res.Records, limit)
	sum.Truncated = sum.Truncated || res.Truncated
	w.Header().Set("X-Netra-Export-Count", fmt.Sprint(len(sum.Flows)))
	w.Header().Set("X-Netra-Export-Truncated", fmt.Sprint(sum.Truncated))
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = flowexport.WriteCSV(w, sum.Flows)
	case "jsonl":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		_ = flowexport.WriteJSONL(w, sum.Flows)
	default:
		writeJSON(w, http.StatusOK, sum)
	}
}
