// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/detective"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/incident"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/timeline"
)

func (s *Server) incidentsTimeline(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			errorJSON(w, 400, "since must be an RFC3339 timestamp, e.g. 2026-09-14T00:00:00Z")
			return
		}
		since = t
	}
	// store.Audit(0) returns everything retained (capped at 1000 events by
	// appendAuditLocked); HealthHistory(zero) returns everything retained
	// (capped at 2h/300 samples) — Build itself narrows both to `since`.
	tl := timeline.Build(s.store.Audit(0), s.store.HealthHistory(time.Time{}), since)
	tl = timeline.Narrate(r.Context(), tl, ai.ProviderFromEnv())
	writeJSON(w, 200, tl)
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("auditLimit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	now := time.Now()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	healthResp := health.Build(agents, 0)
	drift := insights.Drift(s.store.Baseline(), agents)
	rateDrift := s.rateDrift(r)
	graph, err := s.dependencyGraph(r, 5000)
	if err != nil {
		// Degrade gracefully rather than 502 the whole correlator — every
		// join that doesn't need the graph (health/drift/rateDrift/exposure
		// already key off CanonicalSource directly) still works with an
		// empty graph; only detective/audit IP resolution is affected.
		graph = models.DependencyGraph{}
	}
	exposure := insights.Exposure(graph, drift, rateDrift)
	drops := detective.Build(agents, s.store.Config(), 200)
	clusters := incident.Build(healthResp.Summary.Anomalies, drift.Findings, rateDrift.Findings, exposure, drops.Findings, graph, s.store.Audit(limit), now)
	writeJSON(w, 200, map[string]any{"items": clusters, "count": len(clusters)})
}
