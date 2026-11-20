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

	"github.com/zyvorai/netra/internal/encdns"
	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/prevention"
)

func (s *Server) tlsFingerprints(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if s.tlsFP == nil {
		writeJSON(w, 200, map[string]any{
			"fingerprints": []any{}, "stats": map[string]any{"enabled": false, "uniqueJa3": 0},
			"note": "TLS JA3/JA4 fingerprints are collected from L7 datapath ClientHello samples and capture-stream frames (single-skb, no reassembly).",
		})
		return
	}
	writeJSON(w, 200, map[string]any{
		"fingerprints": s.tlsFP.Snapshot(limit),
		"stats":        s.tlsFP.Stats(),
		"note":         "Observe-only. Fed from datapath ClientHello samples (netra_tlsfp tls_hello_events, rate-limited) plus optional capture-stream frames.",
	})
}

func (s *Server) encDNS(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= encdns.MaxHits {
		limit = n
	}
	now := time.Now().UTC()
	res := encdns.Match(s.store.AgentStatuses(now, s.agentStaleAfter), limit)
	writeJSON(w, 200, map[string]any{
		"result": res,
		"note":   "DoT = dest port 853; DoH = known SaaS hostnames via SNI/Host/DNS. No decryption.",
	})
}

func (s *Server) fleetClusters(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	local := fleet.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now)
	peers := fleet.ParsePeers(os.Getenv("NETRA_FLEET_PEERS"))
	name := strings.TrimSpace(os.Getenv("NETRA_CLUSTER_NAME"))
	tenant := strings.TrimSpace(os.Getenv("NETRA_CLUSTER_TENANT"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, 200, fleet.AggregateWithTenant(ctx, name, tenant, local, peers, nil))
}

func (s *Server) insightsZeroTrust(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	graph, err := s.dependencyGraph(r, 500)
	if err != nil {
		// Fall back to agent-only graph (no pod/service enrichment).
		graph = insights.Dependencies(agents, nil, nil, 500)
	}
	drafts := insights.ZeroTrust(graph, agents, limit)
	writeJSON(w, 200, map[string]any{
		"drafts": drafts, "count": len(drafts),
		"note": "Review-only identity-aware suggestions. Durable NetPol remains PacketWolf/Cilium when present.",
	})
}

func (s *Server) preventionReport(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	cfg := s.store.Config()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	in := prevention.Input{
		GeneratedAt: now, Mode: cfg.Mode, LeaseUntil: cfg.EnforceUntil, Agents: agents,
		IntelFeed:   s.intelFeed.Entries(),
		BlockedIPv4: len(cfg.BlockedIPv4), BlockedIPv6: len(cfg.BlockedIPv6),
		BlockedDNS: len(cfg.BlockedDNS), BlockedSNI: len(cfg.BlockedSNI),
	}
	if s.dnsDetector != nil {
		in.DNSFindings = len(s.dnsDetector.Findings())
	}
	if s.scanDetector != nil {
		in.ScanFindings = len(s.scanDetector.Findings())
	}
	if s.tlsFP != nil {
		if st, ok := s.tlsFP.Stats()["uniqueJa3"].(int); ok {
			in.TLSFPUnique = st
		}
	}
	if s.autoMitigate != nil {
		in.AutoMitigateActions = len(s.autoMitigate.StatusSnapshot().Recent)
	}
	writeJSON(w, 200, prevention.Build(in))
}
