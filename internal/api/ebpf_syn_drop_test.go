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

// TestEBPFSynDropRoundTrip guards the SYN-drop-mode flag endpoint: an
// exact-IP+direction pair can be added and removed, independent of
// whether a matching deny entry actually exists.
func TestEBPFSynDropRoundTrip(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"address": "203.0.113.9", "direction": "egress"})
	add := httptest.NewRequest("POST", "/api/v1/ebpf/syn-drop", bytes.NewReader(body))
	add.Header.Set("Authorization", "Bearer ci-test-token")
	add.Header.Set("Content-Type", "application/json")
	addRec := httptest.NewRecorder()
	h.ServeHTTP(addRec, add)
	if addRec.Code != http.StatusOK {
		t.Fatalf("POST syn-drop: want 200, got %d body=%s", addRec.Code, addRec.Body.String())
	}
	var cfg struct {
		SynDrop []struct {
			Address   string `json:"address"`
			Direction string `json:"direction"`
		} `json:"synDrop"`
	}
	if err := json.Unmarshal(addRec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDrop) != 1 || cfg.SynDrop[0].Address != "203.0.113.9" || cfg.SynDrop[0].Direction != "egress" {
		t.Fatalf("syn-drop entry not recorded: %+v", cfg.SynDrop)
	}

	del := httptest.NewRequest("POST", "/api/v1/ebpf/syn-drop/delete", bytes.NewReader(body))
	del.Header.Set("Authorization", "Bearer ci-test-token")
	del.Header.Set("Content-Type", "application/json")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("POST syn-drop/delete: want 200, got %d body=%s", delRec.Code, delRec.Body.String())
	}
	var cfg2 struct {
		SynDrop []any `json:"synDrop"`
	}
	if err := json.Unmarshal(delRec.Body.Bytes(), &cfg2); err != nil {
		t.Fatal(err)
	}
	if len(cfg2.SynDrop) != 0 {
		t.Fatalf("syn-drop entry not removed: %v", cfg2.SynDrop)
	}
}

// TestEBPFSynDropRejectsBoth guards the direction restriction: unlike
// EBPFCIDRRule, "both" is not valid here since the underlying kernel maps
// (syndrop_v4/v6) are inherently per-direction.
func TestEBPFSynDropRejectsBoth(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"address": "203.0.113.9", "direction": "both"})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/syn-drop", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST syn-drop with direction=both: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
