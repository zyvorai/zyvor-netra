// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestPlaybooksAndAuditSummary(t *testing.T) {
	s := testExportServer(t)
	r := httptest.NewRequest("GET", "/api/v1/playbooks", nil)
	rec := httptest.NewRecorder()
	s.playbooks(rec, r)
	if rec.Code != 200 {
		t.Fatalf("playbooks status=%d body=%s", rec.Code, rec.Body.String())
	}
	var book map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &book); err != nil {
		t.Fatal(err)
	}
	if _, ok := book["steps"]; !ok {
		t.Fatalf("%v", book)
	}

	r = httptest.NewRequest("GET", "/api/v1/audit/summary", nil)
	rec = httptest.NewRecorder()
	s.auditSummary(rec, r)
	if rec.Code != 200 {
		t.Fatalf("summary status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sum map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum["total"].(float64) < 1 {
		t.Fatalf("expected audit total >= 1: %v", sum)
	}
}

func TestIntelPreviewDoesNotApply(t *testing.T) {
	s := testExportServer(t)
	r := httptest.NewRequest("POST", "/api/v1/intel/preview", strings.NewReader("203.0.113.10\n10.0.0.0/8\n"))
	rec := httptest.NewRecorder()
	s.intelPreview(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		AutoApplied bool `json:"autoApplied"`
		Preview     struct {
			Count int `json:"count"`
		} `json:"preview"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.AutoApplied || out.Preview.Count != 2 {
		t.Fatalf("%+v body=%s", out, rec.Body.String())
	}
	cfg := s.store.Config()
	if len(cfg.BlockedIPv4) != 0 {
		t.Fatalf("preview must not mutate deny maps: %#v", cfg.BlockedIPv4)
	}
}

func TestExportFlowsFromAgentStats(t *testing.T) {
	s := testExportServer(t)
	s.store.Report(models.AgentReport{
		Node:       "n1",
		ObservedAt: time.Now(),
		Stats: []models.DestinationStat{{
			DestinationIP: "203.0.113.20",
			Port:          443,
			Protocol:      "TCP",
			Packets:       4,
			Bytes:         400,
		}},
	})
	r := httptest.NewRequest("GET", "/api/v1/export/flows?format=jsonl", nil)
	rec := httptest.NewRecorder()
	s.exportFlows(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"class":"flow"`) {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestExportBlocksFromAgentEvents(t *testing.T) {
	s := testExportServer(t)
	s.store.Report(models.AgentReport{
		Node:       "n1",
		ObservedAt: time.Now(),
		Events: []models.FastPathEvent{
			{Action: "blocked", Reason: "deny-cidr", SourceIP: "10.0.0.5", DestinationIP: "203.0.113.20", DestinationPort: 443, Protocol: "TCP", ObservedAt: time.Now()},
			{Action: "allowed", SourceIP: "10.0.0.6", DestinationIP: "203.0.113.21", DestinationPort: 80, Protocol: "TCP", ObservedAt: time.Now()},
		},
	})
	for _, format := range []string{"json", "jsonl", "cef", "syslog", "otlp", "otlp-trace"} {
		r := httptest.NewRequest("GET", "/api/v1/export/blocks?format="+format, nil)
		rec := httptest.NewRecorder()
		s.exportBlocks(rec, r)
		if rec.Code != 200 {
			t.Fatalf("%s: status=%d body=%s", format, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "deny-cidr") {
			t.Fatalf("%s: expected the blocked event, not the allowed one: %s", format, body)
		}
		if strings.Contains(body, "203.0.113.21") {
			t.Fatalf("%s: allowed event leaked into blocks export: %s", format, body)
		}
	}
}

func TestExportBlocksOTLPTraceShape(t *testing.T) {
	s := testExportServer(t)
	s.store.Report(models.AgentReport{
		Node:       "n1",
		ObservedAt: time.Now(),
		Events: []models.FastPathEvent{
			{Action: "dropped", Reason: "syn-drop", SourceIP: "10.0.0.5", DestinationIP: "203.0.113.20", DestinationPort: 443, Protocol: "TCP", ObservedAt: time.Now()},
		},
	})
	r := httptest.NewRequest("GET", "/api/v1/export/blocks?format=otlp-trace", nil)
	rec := httptest.NewRecorder()
	s.exportBlocks(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var doc struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					TraceID string `json:"traceId"`
					SpanID  string `json:"spanId"`
					Status  struct {
						Code int `json:"code"`
					} `json:"status"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
	}
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	if len(spans[0].TraceID) != 32 || len(spans[0].SpanID) != 16 {
		t.Fatalf("bad id lengths: traceId=%q spanId=%q", spans[0].TraceID, spans[0].SpanID)
	}
	if spans[0].Status.Code != 2 {
		t.Fatalf("want STATUS_CODE_ERROR(2), got %d", spans[0].Status.Code)
	}
}

func TestIntelPreviewRequiresAuth(t *testing.T) {
	s := testExportServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/intel/preview", strings.NewReader("1.1.1.1"))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("want 401 got %d", rec.Code)
	}
}
