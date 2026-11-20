package api

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/auditstats"
	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/handoff"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/reasons"
	"github.com/zyvorai/netra/internal/scorecard"
	"github.com/zyvorai/netra/internal/sysres"
	"github.com/zyvorai/netra/internal/talkers"
	"github.com/zyvorai/netra/internal/watchlist"
)

func (s *Server) fleetInventory(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	writeJSON(w, 200, fleet.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now))
}

func (s *Server) nodeResources(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	limit := 20
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, sysres.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now, limit))
}

func (s *Server) topTalkers(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	limit := 20
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	writeJSON(w, 200, talkers.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now, limit))
}

func (s *Server) dropReasons(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	writeJSON(w, 200, reasons.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now))
}

func (s *Server) operatorScorecard(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	writeJSON(w, 200, scorecard.Build(s.buildOperatorReport(r, now), coverage.Build(agents, now), fleet.Build(agents, now), reasons.Build(agents, now), now))
}

func (s *Server) operatorHandoff(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "md" && format != "json" {
		errorJSON(w, 400, "format must be markdown or json")
		return
	}
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	pack := handoff.Build(s.buildOperatorReport(r, now), coverage.Build(agents, now), fleet.Build(agents, now), auditstats.Summarize(s.store.Audit(500), time.Time{}, time.Time{}), reasons.Build(agents, now), now)
	if format == "json" {
		writeJSON(w, 200, pack)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(handoff.Markdown(pack)))
}

func (s *Server) watchlistMatch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	preview, err := intel.Parse(string(body))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= watchlist.MaxHits {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, map[string]any{
		"preview": preview, "match": watchlist.Match(s.store.AgentStatuses(now, s.agentStaleAfter), preview.Entries, limit),
		"autoApplied": false, "note": "Watchlist match is observe-only.",
	})
}
