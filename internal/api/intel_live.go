// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/ainet"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/watchlist"
)

func (s *Server) intelFeedGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"feed":    s.intelFeed.Status(),
		"entries": s.intelFeed.Entries(),
		"note":    "Active threat-intel list. Match is observe-only; apply requires enforce lease + confirm.",
	})
}

func (s *Server) intelFeedPut(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if len(body) > 1<<20 {
		errorJSON(w, http.StatusRequestEntityTooLarge, "intel feed exceeds 1 MiB")
		return
	}
	preview, err := intel.Parse(string(body))
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	source := strings.TrimSpace(r.Header.Get("X-Netra-Intel-Source"))
	if source == "" {
		source = "operator"
	}
	note := strings.TrimSpace(r.URL.Query().Get("note"))
	if len(source) > 512 || len(note) > 1024 {
		errorJSON(w, 400, "intel source/note too long")
		return
	}
	expected, err := intelExpected(r)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	ttl := time.Duration(0)
	if v := r.URL.Query().Get("ttl"); v != "" {
		ttl, err = time.ParseDuration(v)
		if err != nil || ttl < 0 || ttl > 720*time.Hour {
			errorJSON(w, 400, "ttl must be 0..720h")
			return
		}
	}
	st, err := s.intelFeed.Put(preview, source, note, ttl, expected)
	if err != nil {
		intelWriteError(w, err)
		return
	}
	recorded := s.store.AddAudit(models.AuditEvent{At: time.Now().UTC(), Actor: actor(r), Action: "intel.put", Target: strconv.FormatUint(st.Revision, 10)}) == nil
	writeJSON(w, 200, map[string]any{
		"feed":          st,
		"preview":       preview,
		"auditRecorded": recorded,
		"autoApplied":   false,
		"applyHint":     "POST /api/v1/intel/apply with X-Netra-Confirm-Risk: high while mode=enforce (leased)",
	})
}

func (s *Server) intelFeedDelete(w http.ResponseWriter, r *http.Request) {
	expected, err := intelExpected(r)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	st, err := s.intelFeed.Put(intel.Preview{}, "operator", "cleared", 0, expected)
	if err != nil {
		intelWriteError(w, err)
		return
	}
	recorded := s.store.AddAudit(models.AuditEvent{At: time.Now().UTC(), Actor: actor(r), Action: "intel.clear", Target: strconv.FormatUint(st.Revision, 10)}) == nil
	writeJSON(w, 200, map[string]any{"feed": st, "autoApplied": false, "auditRecorded": recorded})
}

func (s *Server) intelHits(w http.ResponseWriter, r *http.Request) {
	entries := s.intelFeed.Entries()
	if len(entries) == 0 {
		writeJSON(w, 200, map[string]any{
			"feed": s.intelFeed.Status(), "match": watchlist.Result{Hits: []watchlist.Hit{}},
			"autoApplied": false, "note": "No active feed. PUT /api/v1/intel/feed first.",
		})
		return
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= watchlist.MaxHits {
		limit = n
	}
	now := time.Now().UTC()
	writeJSON(w, 200, map[string]any{
		"feed":        s.intelFeed.Status(),
		"match":       watchlist.Match(s.store.AgentStatuses(now, s.agentStaleAfter), entries, limit),
		"autoApplied": false,
		"note":        "Observe-only match of the active feed against live agent metadata.",
	})
}

// intelApply imports the active feed (or matched-only subset) into deny maps.
// Requires an active enforce lease and X-Netra-Confirm-Risk: high.
func (s *Server) intelApply(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), "high") {
		errorJSON(w, 409, "applying threat-intel requires X-Netra-Confirm-Risk: high")
		return
	}
	cfg := s.store.Config()
	if cfg.Mode != "enforce" || cfg.EnforceUntil == nil || !time.Now().Before(*cfg.EnforceUntil) {
		errorJSON(w, 409, "intel apply requires mode=enforce with an active lease")
		return
	}
	entries := s.intelFeed.Entries()
	if len(entries) == 0 {
		errorJSON(w, 400, "active feed is empty")
		return
	}
	matchedOnly := r.URL.Query().Get("matchedOnly") == "true" || r.URL.Query().Get("matchedOnly") == "1"
	if matchedOnly {
		match := watchlist.Match(s.store.AgentStatuses(time.Now().UTC(), s.agentStaleAfter), entries, watchlist.MaxHits)
		seen := map[string]bool{}
		var filtered []intel.Entry
		for _, h := range match.Hits {
			key := h.Type + "|" + h.Value
			if seen[key] {
				continue
			}
			seen[key] = true
			filtered = append(filtered, intel.Entry{Type: h.Type, Value: h.Value, Direction: "egress"})
		}
		entries = filtered
		if len(entries) == 0 {
			writeJSON(w, 200, map[string]any{"applied": 0, "failed": 0, "results": []any{}, "note": "no live matches to apply"})
			return
		}
	}
	act := actor(r)
	results := make([]denyImportResult, len(entries))
	applied, failed := 0, 0
	var outCfg = cfg
	for i, e := range entries {
		res := denyImportResult{Index: i}
		newCfg, err := s.applyDenyImportEntry(denyImportEntry{Type: e.Type, Value: e.Value, Direction: e.Direction}, act)
		if err != nil {
			res.Error = err.Error()
			failed++
		} else {
			res.OK = true
			outCfg = newCfg
			applied++
		}
		results[i] = res
	}
	writeJSON(w, 200, map[string]any{
		"results": results, "applied": applied, "failed": failed, "config": outCfg,
		"matchedOnly": matchedOnly,
		"note":        "Deny entries active only while enforce lease holds; fails open on expiry.",
	})
}

func (s *Server) aiDestinations(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= ainet.MaxHits {
		limit = n
	}
	now := time.Now().UTC()
	res := ainet.Match(s.store.AgentStatuses(now, s.agentStaleAfter), ainet.DefaultCatalog(), limit)
	writeJSON(w, 200, map[string]any{
		"result":      res,
		"autoApplied": false,
		"applyHint":   "POST /api/v1/ebpf/ai-destinations/deny with X-Netra-Confirm-Risk: high while mode=enforce (leased)",
		"note":        "Metadata-only (SNI/Host/DNS). No prompts or payloads inspected.",
	})
}

func (s *Server) aiDestinationsDeny(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), "high") {
		errorJSON(w, 409, "denying AI destinations requires X-Netra-Confirm-Risk: high")
		return
	}
	cfg := s.store.Config()
	if cfg.Mode != "enforce" || cfg.EnforceUntil == nil || !time.Now().Before(*cfg.EnforceUntil) {
		errorJSON(w, 409, "AI destination deny requires mode=enforce with an active lease")
		return
	}
	now := time.Now().UTC()
	hits := ainet.Match(s.store.AgentStatuses(now, s.agentStaleAfter), ainet.DefaultCatalog(), ainet.MaxHits).Hits
	entries := ainet.DenyEntries(hits)
	if len(entries) == 0 {
		writeJSON(w, 200, map[string]any{"applied": 0, "failed": 0, "results": []any{}, "note": "no AI/MCP destinations observed"})
		return
	}
	act := actor(r)
	results := make([]denyImportResult, len(entries))
	applied, failed := 0, 0
	var outCfg = cfg
	for i, e := range entries {
		res := denyImportResult{Index: i}
		newCfg, err := s.applyDenyImportEntry(denyImportEntry{Type: e.Type, Value: e.Value, Direction: e.Direction}, act)
		if err != nil {
			res.Error = err.Error()
			failed++
		} else {
			res.OK = true
			outCfg = newCfg
			applied++
		}
		results[i] = res
	}
	writeJSON(w, 200, map[string]any{
		"results": results, "applied": applied, "failed": failed, "config": outCfg,
		"note": "SNI denies for observed GenAI/MCP SaaS hosts; lease-bounded.",
	})
}

func (s *Server) autoMitigateStatus(w http.ResponseWriter, _ *http.Request) {
	if s.autoMitigate == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "recent": []any{}, "note": "set NETRA_AUTOMITIGATE_ENABLED=true"})
		return
	}
	writeJSON(w, 200, s.autoMitigate.StatusSnapshot())
}
