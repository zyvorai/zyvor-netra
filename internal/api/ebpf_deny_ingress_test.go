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

// TestEBPFDenyAddSupportsDirection guards the new "direction" field on
// POST /api/v1/ebpf/deny: an ingress deny must land in the ingress-only
// store lists, not the (pre-existing) egress ones.
func TestEBPFDenyAddSupportsDirection(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"ip": "203.0.113.9", "direction": "ingress"})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/deny", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST deny with direction=ingress: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var cfg struct {
		BlockedIPv4        []string `json:"blockedIPv4"`
		BlockedIngressIPv4 []string `json:"blockedIngressIPv4"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedIPv4) != 0 {
		t.Fatalf("ingress-only deny leaked into egress list: %v", cfg.BlockedIPv4)
	}
	if len(cfg.BlockedIngressIPv4) != 1 || cfg.BlockedIngressIPv4[0] != "203.0.113.9" {
		t.Fatalf("ingress deny not recorded: %v", cfg.BlockedIngressIPv4)
	}
}

// TestEBPFDenyDeleteClearsBothDirections guards a real bug found while
// adding web UI for directional deny: DELETE /api/v1/ebpf/deny/{ip} only
// ever cleared the egress blocked_v4/v6 lists, never the new
// blocked_ingress_v4/v6 lists — so an ingress-deny chip's "remove" button
// in the dashboard would silently do nothing. A single DELETE by IP must
// now clear whichever direction(s) actually contain it.
func TestEBPFDenyDeleteClearsBothDirections(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	add := func(direction string) {
		body, _ := json.Marshal(map[string]any{"ip": "203.0.113.10", "direction": direction})
		req := httptest.NewRequest("POST", "/api/v1/ebpf/deny", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer ci-test-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST deny direction=%s: want 200, got %d body=%s", direction, rec.Code, rec.Body.String())
		}
	}
	add("egress")
	add("ingress")

	del := httptest.NewRequest("DELETE", "/api/v1/ebpf/deny/203.0.113.10", nil)
	del.Header.Set("Authorization", "Bearer ci-test-token")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE deny: want 200, got %d body=%s", delRec.Code, delRec.Body.String())
	}
	var cfg struct {
		BlockedIPv4        []string `json:"blockedIPv4"`
		BlockedIngressIPv4 []string `json:"blockedIngressIPv4"`
	}
	if err := json.Unmarshal(delRec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.BlockedIPv4) != 0 {
		t.Fatalf("egress deny not cleared: %v", cfg.BlockedIPv4)
	}
	if len(cfg.BlockedIngressIPv4) != 0 {
		t.Fatalf("ingress deny not cleared: %v", cfg.BlockedIngressIPv4)
	}
}
