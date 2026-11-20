// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/appcat"
	"github.com/zyvorai/netra/internal/catdeny"
	"github.com/zyvorai/netra/internal/dnsintel"
	"github.com/zyvorai/netra/internal/echblind"
	"github.com/zyvorai/netra/internal/exfil"
	"github.com/zyvorai/netra/internal/lateral"
	"github.com/zyvorai/netra/internal/tlsfp"
)

func (s *Server) tlsFingerprintRisk(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if s.tlsFP == nil {
		writeJSON(w, 200, tlsfp.RiskBoard{Items: []tlsfp.RiskItem{}, Note: "TLS fingerprint detector disabled."})
		return
	}
	writeJSON(w, 200, s.tlsFP.Risk(limit, 2))
}

func (s *Server) insightsECHBlind(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= echblind.MaxFindings {
		limit = n
	}
	now := time.Now().UTC()
	var fps []tlsfp.Observation
	if s.tlsFP != nil {
		fps = s.tlsFP.Snapshot(200)
	}
	writeJSON(w, 200, echblind.Build(s.store.AgentStatuses(now, s.agentStaleAfter), fps, limit))
}

func (s *Server) insightsExfil(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= exfil.MaxFindings {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, exfil.Build(s.store.AgentStatuses(now, s.agentStaleAfter), limit))
}

func (s *Server) insightsLateral(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= lateral.MaxPlaybooks {
		limit = n
	}
	if s.scanDetector == nil {
		writeJSON(w, 200, lateral.Build(nil, limit))
		return
	}
	writeJSON(w, 200, lateral.Build(s.scanDetector.Findings(), limit))
}

func (s *Server) insightsCategoryDeny(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= catdeny.MaxDrafts {
		limit = n
	}
	var targets []appcat.Category
	if raw := strings.TrimSpace(r.URL.Query().Get("categories")); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p != "" {
				targets = append(targets, appcat.Category(p))
			}
		}
	}
	now := time.Now().UTC()
	writeJSON(w, 200, catdeny.Build(s.store.AgentStatuses(now, s.agentStaleAfter), targets, limit))
}

func (s *Server) intelDNSHits(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= dnsintel.MaxHits {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, dnsintel.Build(s.store.AgentStatuses(now, s.agentStaleAfter), s.intelFeed.Entries(), limit))
}
