// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func testExportServer(t *testing.T) *Server {
	t.Helper()
	st := store.New()
	if err := st.AddAudit(models.AuditEvent{Actor: "netractl", Action: "ebpf.mode", Target: "enforce"}); err != nil {
		t.Fatal(err)
	}
	return &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:       st,
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		intelFeed:   &intel.Feed{},
	}
}

func TestExportAuditFormats(t *testing.T) {
	s := testExportServer(t)
	for _, format := range []string{"json", "jsonl", "cef", "syslog", "otlp"} {
		r := httptest.NewRequest("GET", "/api/v1/export/audit?format="+format, nil)
		rec := httptest.NewRecorder()
		s.exportAudit(rec, r)
		if rec.Code != 200 {
			t.Fatalf("%s: status=%d body=%s", format, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		switch format {
		case "json", "otlp":
			var m map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
				t.Fatalf("%s: %v", format, err)
			}
		case "cef":
			if !strings.Contains(body, "CEF:0|Zyvor|Netra|") {
				t.Fatalf("cef body: %s", body)
			}
		case "syslog":
			if !strings.Contains(body, " netra ") {
				t.Fatalf("syslog body: %s", body)
			}
		case "jsonl":
			if !strings.Contains(body, `"class":"audit"`) {
				t.Fatalf("jsonl body: %s", body)
			}
		}
	}
}

func TestExportAuditRejectsUnknownFormat(t *testing.T) {
	s := testExportServer(t)
	r := httptest.NewRequest("GET", "/api/v1/export/audit?format=pcap", nil)
	rec := httptest.NewRecorder()
	s.exportAudit(rec, r)
	if rec.Code != 400 {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestOperatorReportMarkdownAndJSON(t *testing.T) {
	s := testExportServer(t)
	r := httptest.NewRequest("GET", "/api/v1/report", nil)
	rec := httptest.NewRecorder()
	s.operatorReport(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "markdown") {
		t.Fatalf("content-type: %s", ct)
	}
	if !strings.Contains(rec.Body.String(), "# Netra operator report") {
		t.Fatalf("body: %s", rec.Body.String())
	}

	r = httptest.NewRequest("GET", "/api/v1/report?format=json", nil)
	rec = httptest.NewRecorder()
	s.operatorReport(rec, r)
	if rec.Code != 200 {
		t.Fatalf("json status=%d body=%s", rec.Code, rec.Body.String())
	}
	var snap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if _, ok := snap["headline"]; !ok {
		t.Fatalf("missing headline: %v", snap)
	}
}

func TestExportRoutesRequireAuth(t *testing.T) {
	s := testExportServer(t)
	h := s.Handler()
	for _, path := range []string{"/api/v1/export/audit", "/api/v1/export/events", "/api/v1/export/flows", "/api/v1/export/blocks", "/api/v1/report", "/api/v1/playbooks", "/api/v1/ebpf/coverage"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("%s: want 401, got %d", path, rec.Code)
		}
	}
}
