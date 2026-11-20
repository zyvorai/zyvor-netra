package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/baselineage"
	"github.com/zyvorai/netra/internal/denycensus"
	"github.com/zyvorai/netra/internal/dnsboard"
	"github.com/zyvorai/netra/internal/ebpfmaps"
	"github.com/zyvorai/netra/internal/leaseclock"
	"github.com/zyvorai/netra/internal/nsheat"
	"github.com/zyvorai/netra/internal/portheat"
	"github.com/zyvorai/netra/internal/protomix"
)

func (s *Server) namespaceHeat(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	limit := 30
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, nsheat.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now, limit))
}

func (s *Server) protocolMix(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	writeJSON(w, 200, protomix.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now))
}

func (s *Server) denyCensus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, denycensus.Build(s.store.Config(), time.Now().UTC()))
}

func (s *Server) ebpfMaps(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, ebpfmaps.Build(s.store.Config(), time.Now().UTC()))
}

func (s *Server) baselineStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, baselineage.Build(s.store.Baseline(), s.store.RateBaseline(), time.Now().UTC(), 24*time.Hour))
}

func (s *Server) portHeat(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	limit := 30
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, portheat.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now, limit))
}

func (s *Server) dnsBoard(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	limit := 30
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, dnsboard.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now, limit))
}

func (s *Server) leaseStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, leaseclock.Build(s.store.Config(), time.Now().UTC()))
}
