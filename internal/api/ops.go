// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/auditstats"
	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/playbook"
	"github.com/zyvorai/netra/internal/siem"
)

func (s *Server) playbooks(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	snap := s.buildOperatorReport(r, now)
	book := playbook.Build(snap)
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "markdown" || format == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(playbook.Markdown(book)))
		return
	}
	writeJSON(w, 200, book)
}

func (s *Server) auditSummary(w http.ResponseWriter, r *http.Request) {
	limit := parseExportLimit(r, 500, 1000)
	var since, until time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			errorJSON(w, 400, "since must be RFC3339")
			return
		}
		since = t
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			errorJSON(w, 400, "until must be RFC3339")
			return
		}
		until = t
	}
	writeJSON(w, 200, auditstats.Summarize(s.store.Audit(limit), since, until))
}

func (s *Server) exportFlows(w http.ResponseWriter, r *http.Request) {
	format, ok := parseExportFormat(w, r)
	if !ok {
		return
	}
	limit := parseExportLimit(r, 200, 2000)
	now := time.Now().UTC()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	records := make([]siem.Record, 0, limit)
	for _, a := range agents {
		for _, st := range a.Stats {
			if len(records) >= limit {
				break
			}
			records = append(records, siem.FromFlow(a.Node, st, now))
		}
		if len(records) >= limit {
			break
		}
	}
	writeExport(w, format, records)
}

func (s *Server) intelPreview(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, 200, map[string]any{
		"preview":     preview,
		"applyHint":   "POST /api/v1/ebpf/deny/import with {\"entries\": preview.entries} — this preview applied nothing",
		"autoApplied": false,
	})
}

func (s *Server) ebpfCoverage(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	writeJSON(w, 200, coverage.Build(s.store.AgentStatuses(now, s.agentStaleAfter), now))
}

func (s *Server) exportStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"formats": []string{siem.FormatJSON, siem.FormatJSONL, siem.FormatCEF, siem.FormatSyslog, siem.FormatOTLP, siem.FormatOTLPTrace},
		"pull": []string{
			"GET /api/v1/export/audit",
			"GET /api/v1/export/events",
			"GET /api/v1/export/flows",
			"GET /api/v1/export/blocks",
			"GET /api/v1/report",
			"GET /api/v1/playbooks",
		},
		"syslogAddr":    strings.TrimSpace(os.Getenv("NETRA_SYSLOG_ADDR")),
		"syslogNetwork": firstNonEmpty(strings.TrimSpace(os.Getenv("NETRA_SYSLOG_NETWORK")), "udp"),
		"syslogFormat":  firstNonEmpty(strings.TrimSpace(os.Getenv("NETRA_SYSLOG_FORMAT")), "syslog"),
		"syslogEnabled": strings.TrimSpace(os.Getenv("NETRA_SYSLOG_ADDR")) != "",
		"note":          "Syslog push is best-effort and leader-only in HA. Pull export always works.",
	})
}

func firstNonEmpty(v, d string) string {
	if v != "" {
		return v
	}
	return d
}
