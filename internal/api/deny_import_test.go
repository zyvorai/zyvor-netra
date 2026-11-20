// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/store"
)

// TestEBPFDenyImportPartialSuccess guards the bulk deny-import endpoint:
// it dispatches each entry through the existing per-type validators and
// reports success/failure per entry rather than failing the whole batch.
func TestEBPFDenyImportPartialSuccess(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"entries": []map[string]string{
		{"type": "ip", "value": "203.0.113.5"},
		{"type": "cidr", "value": "10.0.0.0/8", "direction": "ingress"},
		{"type": "dns", "value": "evil.example.com"},
		{"type": "sni", "value": "evil.example.com"},
		{"type": "ip", "value": "not-an-ip"},
		{"type": "bogus", "value": "x"},
	}})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/deny/import", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Results []struct {
			Index int    `json:"index"`
			OK    bool   `json:"ok"`
			Error string `json:"error,omitempty"`
		} `json:"results"`
		Applied int `json:"applied"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Applied != 4 || out.Failed != 2 {
		t.Fatalf("applied=%d failed=%d results=%+v", out.Applied, out.Failed, out.Results)
	}
	if len(out.Results) != 6 || out.Results[4].OK || out.Results[5].OK {
		t.Fatalf("unexpected per-entry results: %+v", out.Results)
	}

	cfg := s.store.Config()
	if len(cfg.BlockedIPv4) != 1 || len(cfg.BlockedCIDRs) != 1 || len(cfg.BlockedDNS) != 1 || len(cfg.BlockedSNI) != 1 {
		t.Fatalf("entries not applied to store: %+v", cfg)
	}
}

func TestEBPFDenyImportRejectsEmptyAndOversized(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	empty, _ := json.Marshal(map[string]any{"entries": []map[string]string{}})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/deny/import", bytes.NewReader(empty))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("empty entries: want 400, got %d", rec.Code)
	}

	entries := make([]map[string]string, 1001)
	for i := range entries {
		entries[i] = map[string]string{"type": "dns", "value": "x.example.com"}
	}
	oversized, _ := json.Marshal(map[string]any{"entries": entries})
	req2 := httptest.NewRequest("POST", "/api/v1/ebpf/deny/import", bytes.NewReader(oversized))
	req2.Header.Set("Authorization", "Bearer ci-test-token")
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 400 {
		t.Fatalf("oversized entries: want 400, got %d", rec2.Code)
	}
}
