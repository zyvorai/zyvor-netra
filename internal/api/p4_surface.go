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
	"github.com/zyvorai/netra/internal/identitydraft"
	"github.com/zyvorai/netra/internal/policypack"
	"github.com/zyvorai/netra/internal/shadowsaas"
)

func (s *Server) insightsPolicyPacks(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= policypack.MaxPacks {
		limit = n
	}
	sanctioned := shadowsaas.ParseSanctioned(os.Getenv("NETRA_SANCTIONED_HOSTS"))
	now := time.Now().UTC()
	writeJSON(w, 200, policypack.Build(s.store.AgentStatuses(now, s.agentStaleAfter), sanctioned, limit))
}

func (s *Server) insightsIdentityDrafts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= identitydraft.MaxDrafts {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, identitydraft.Build(s.store.AgentStatuses(now, s.agentStaleAfter), limit))
}

func (s *Server) fleetTenants(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	local := fleet.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now)
	peers := fleet.ParsePeers(os.Getenv("NETRA_FLEET_PEERS"))
	name := strings.TrimSpace(os.Getenv("NETRA_CLUSTER_NAME"))
	tenant := strings.TrimSpace(os.Getenv("NETRA_CLUSTER_TENANT"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	mc := fleet.AggregateWithTenant(ctx, name, tenant, local, peers, nil)
	writeJSON(w, 200, fleet.RollupTenants(mc))
}
