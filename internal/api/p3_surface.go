// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/destrisk"
	"github.com/zyvorai/netra/internal/experience"
	"github.com/zyvorai/netra/internal/shadowsaas"
)

func (s *Server) insightsShadowSaaS(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= shadowsaas.MaxFindings {
		limit = n
	}
	sanctioned := shadowsaas.ParseSanctioned(os.Getenv("NETRA_SANCTIONED_HOSTS"))
	now := time.Now().UTC()
	writeJSON(w, 200, shadowsaas.Build(s.store.AgentStatuses(now, s.agentStaleAfter), sanctioned, limit))
}

func (s *Server) insightsExperience(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= experience.MaxRows {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, experience.Build(s.store.AgentStatuses(now, s.agentStaleAfter), limit))
}

func (s *Server) insightsDestinationRisk(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= destrisk.MaxItems {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, destrisk.Build(s.store.AgentStatuses(now, s.agentStaleAfter), s.intelFeed.Entries(), limit))
}
