// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/incident"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/report"
	"github.com/zyvorai/netra/internal/siem"
)

func parseExportFormat(w http.ResponseWriter, r *http.Request) (string, bool) {
	f, err := siem.NormalizeFormat(r.URL.Query().Get("format"))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return "", false
	}
	return f, true
}

func parseExportLimit(r *http.Request, def, max int) int {
	limit := def
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= max {
		limit = n
	}
	return limit
}

func writeExport(w http.ResponseWriter, format string, records []siem.Record) {
	body, err := siem.Encode(format, records)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	w.Header().Set("Content-Type", siem.ContentType(format))
	w.Header().Set("X-Netra-Export-Format", format)
	w.Header().Set("X-Netra-Export-Count", strconv.Itoa(len(records)))
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	format, ok := parseExportFormat(w, r)
	if !ok {
		return
	}
	limit := parseExportLimit(r, 100, 500)
	events := s.store.Audit(limit)
	records := make([]siem.Record, 0, len(events))
	for _, e := range events {
		records = append(records, siem.FromAudit(e))
	}
	writeExport(w, format, records)
}

func (s *Server) exportEvents(w http.ResponseWriter, r *http.Request) {
	format, ok := parseExportFormat(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	healthResp := health.Build(agents, 0)
	include := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include")))
	if include == "" {
		include = "anomaly,incident"
	}
	want := map[string]bool{}
	for _, part := range strings.Split(include, ",") {
		want[strings.TrimSpace(part)] = true
	}
	var records []siem.Record
	if want["anomaly"] || want["anomalies"] {
		for _, a := range healthResp.Summary.Anomalies {
			records = append(records, siem.FromAnomaly(a, now))
		}
	}
	if want["incident"] || want["incidents"] {
		for _, c := range s.incidentClusters(r, now, agents, healthResp) {
			records = append(records, siem.FromIncident(c))
		}
	}
	if want["audit"] {
		for _, e := range s.store.Audit(parseExportLimit(r, 100, 500)) {
			records = append(records, siem.FromAudit(e))
		}
	}
	writeExport(w, format, records)
}

// exportBlocks emits current blocked/dropped FastPathEvents across
// fresh agents as SIEM records — the same encodings exportFlows uses,
// plus otlp-trace (each blocked event becomes one OTLP span; see
// docs/exporter-tetragon-borrow-backlog.md's "OTEL spans for
// block/deny" item). Observe-only: reads already-captured events,
// applies nothing.
func (s *Server) exportBlocks(w http.ResponseWriter, r *http.Request) {
	format, ok := parseExportFormat(w, r)
	if !ok {
		return
	}
	limit := parseExportLimit(r, 200, 2000)
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	records := make([]siem.Record, 0, limit)
	for _, a := range agents {
		for _, ev := range a.Events {
			if !siem.IsBlocked(ev.Action) {
				continue
			}
			if len(records) >= limit {
				break
			}
			records = append(records, siem.FromBlockEvent(a.Node, ev))
		}
		if len(records) >= limit {
			break
		}
	}
	writeExport(w, format, records)
}

func (s *Server) operatorReport(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "md" && format != "json" {
		errorJSON(w, 400, "format must be markdown or json")
		return
	}
	now := time.Now().UTC()
	snap := s.buildOperatorReport(r, now)
	if format == "json" {
		writeJSON(w, 200, snap)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(report.Markdown(snap)))
}

func (s *Server) buildOperatorReport(r *http.Request, now time.Time) report.Snapshot {
	cfg := s.store.Config()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	stale := 0
	var packets, blocked uint64
	for _, a := range agents {
		if a.Stale {
			stale++
		}
		for _, st := range a.Stats {
			packets += st.Packets
			blocked += st.Blocked
		}
	}
	healthResp := health.Build(agents, 0)
	drift := insights.Drift(s.store.Baseline(), agents)
	rateDrift := s.rateDrift(r)
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		graph = models.DependencyGraph{}
	}
	exposure := insights.Exposure(graph, drift, rateDrift)
	highExposure := 0
	for _, item := range exposure {
		if item.Severity == "high" || item.Severity == "critical" {
			highExposure++
		}
	}
	clusters := s.incidentClusters(r, now, agents, healthResp)
	var lease time.Time
	if cfg.EnforceUntil != nil {
		lease = *cfg.EnforceUntil
	}
	in := report.Input{
		GeneratedAt:     now,
		Version:         "0.27.71",
		Mode:            cfg.Mode,
		ScopeMode:       cfg.ScopeMode,
		LeaseExpiresAt:  lease,
		Agents:          len(agents),
		StaleAgents:     stale,
		HealthScore:     healthResp.Summary.HealthScore,
		Packets:         packets,
		Blocked:         blocked,
		TCPRetrans:      healthResp.Summary.TCPRetransmissions,
		DNSFailures:     healthResp.Summary.DNSFailures,
		Anomalies:       healthResp.Summary.Anomalies,
		DriftFindings:   len(drift.Findings),
		RateDrift:       len(rateDrift.Findings),
		HighExposure:    highExposure,
		Incidents:       len(clusters),
		BaselineAt:      s.store.Baseline().CapturedAt,
		RateBaselineAt:  s.store.RateBaseline().CapturedAt,
		Audit:           s.store.Audit(8),
		TopAnomalies:    healthResp.Summary.Anomalies,
		IncidentSamples: clusters,
	}
	return report.Build(in)
}

func (s *Server) incidentClusters(r *http.Request, now time.Time, agents []models.AgentStatus, healthResp models.NetworkHealthResponse) []models.IncidentCluster {
	drift := insights.Drift(s.store.Baseline(), agents)
	rateDrift := s.rateDrift(r)
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		graph = models.DependencyGraph{}
	}
	exposure := insights.Exposure(graph, drift, rateDrift)
	drops := detective.Build(agents, s.store.Config(), 200)
	return incident.Build(healthResp.Summary.Anomalies, drift.Findings, rateDrift.Findings, exposure, drops.Findings, graph, s.store.Audit(200), now)
}
