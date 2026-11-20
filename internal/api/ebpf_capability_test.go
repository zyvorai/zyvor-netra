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

// TestEBPFCapabilityRoundTrip guards the capability-gated socket deny
// list endpoint.
func TestEBPFCapabilityRoundTrip(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"name": "cap_net_raw"})
	add := httptest.NewRequest("POST", "/api/v1/ebpf/capability", bytes.NewReader(body))
	add.Header.Set("Authorization", "Bearer ci-test-token")
	add.Header.Set("Content-Type", "application/json")
	addRec := httptest.NewRecorder()
	h.ServeHTTP(addRec, add)
	if addRec.Code != http.StatusOK {
		t.Fatalf("POST capability: want 200, got %d body=%s", addRec.Code, addRec.Body.String())
	}
	var cfg struct {
		DeniedCapabilities []string `json:"deniedCapabilities"`
	}
	if err := json.Unmarshal(addRec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	// Lowercase input must be normalized to the canonical uppercase name.
	if len(cfg.DeniedCapabilities) != 1 || cfg.DeniedCapabilities[0] != "CAP_NET_RAW" {
		t.Fatalf("capability entry not recorded/normalized: %+v", cfg.DeniedCapabilities)
	}

	del := httptest.NewRequest("POST", "/api/v1/ebpf/capability/delete", bytes.NewReader(body))
	del.Header.Set("Authorization", "Bearer ci-test-token")
	del.Header.Set("Content-Type", "application/json")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("POST capability/delete: want 200, got %d body=%s", delRec.Code, delRec.Body.String())
	}
	var cfg2 struct {
		DeniedCapabilities []any `json:"deniedCapabilities"`
	}
	if err := json.Unmarshal(delRec.Body.Bytes(), &cfg2); err != nil {
		t.Fatal(err)
	}
	if len(cfg2.DeniedCapabilities) != 0 {
		t.Fatalf("capability entry not removed: %v", cfg2.DeniedCapabilities)
	}
}

// TestEBPFCapabilityRejectsUnknownName guards the fixed vocabulary:
// unlike process names, capability names are validated against a known,
// small set (models.CapabilityBit) rather than accepted as arbitrary
// strings.
func TestEBPFCapabilityRejectsUnknownName(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"name": "CAP_SYS_ADMIN"})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/capability", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST capability with an unsupported name: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
