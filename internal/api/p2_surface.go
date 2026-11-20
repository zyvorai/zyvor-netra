// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/appcat"
	"github.com/zyvorai/netra/internal/compliance"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/microseg"
	"github.com/zyvorai/netra/internal/models"
)

func (s *Server) appCategories(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= appcat.MaxHits {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, appcat.Match(s.store.AgentStatuses(now, s.agentStaleAfter), nil, limit))
}

func (s *Server) complianceReport(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, compliance.Build(s.store.AgentStatuses(now, s.agentStaleAfter), limit))
}

func (s *Server) insightsMicroseg(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 100 {
		limit = n
	}
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	var graph models.DependencyGraph
	if g, err := s.dependencyGraph(r, 500); err == nil {
		graph = g
	} else {
		graph = insights.Dependencies(agents, nil, nil, 500)
	}
	writeJSON(w, 200, microseg.Build(graph, agents, s.ciliumEnabled, limit))
}
