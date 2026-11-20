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

// TestEBPFSynDropCIDRRoundTrip guards the CIDR SYN-drop-mode flag endpoint:
// a CIDR+direction pair can be added and removed, independent of whether a
// matching CIDR deny entry actually exists — mirroring
// TestEBPFSynDropRoundTrip for the exact-IP variant.
func TestEBPFSynDropCIDRRoundTrip(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"cidr": "203.0.113.0/24", "direction": "egress"})
	add := httptest.NewRequest("POST", "/api/v1/ebpf/syn-drop-cidr", bytes.NewReader(body))
	add.Header.Set("Authorization", "Bearer ci-test-token")
	add.Header.Set("Content-Type", "application/json")
	addRec := httptest.NewRecorder()
	h.ServeHTTP(addRec, add)
	if addRec.Code != http.StatusOK {
		t.Fatalf("POST syn-drop-cidr: want 200, got %d body=%s", addRec.Code, addRec.Body.String())
	}
	var cfg struct {
		SynDropCIDR []struct {
			CIDR      string `json:"cidr"`
			Direction string `json:"direction"`
		} `json:"synDropCidr"`
	}
	if err := json.Unmarshal(addRec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.SynDropCIDR) != 1 || cfg.SynDropCIDR[0].CIDR != "203.0.113.0/24" || cfg.SynDropCIDR[0].Direction != "egress" {
		t.Fatalf("syn-drop-cidr entry not recorded: %+v", cfg.SynDropCIDR)
	}

	del := httptest.NewRequest("POST", "/api/v1/ebpf/syn-drop-cidr/delete", bytes.NewReader(body))
	del.Header.Set("Authorization", "Bearer ci-test-token")
	del.Header.Set("Content-Type", "application/json")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("POST syn-drop-cidr/delete: want 200, got %d body=%s", delRec.Code, delRec.Body.String())
	}
	var cfg2 struct {
		SynDropCIDR []any `json:"synDropCidr"`
	}
	if err := json.Unmarshal(delRec.Body.Bytes(), &cfg2); err != nil {
		t.Fatal(err)
	}
	if len(cfg2.SynDropCIDR) != 0 {
		t.Fatalf("syn-drop-cidr entry not removed: %v", cfg2.SynDropCIDR)
	}
}

// TestEBPFSynDropCIDRRejectsBoth mirrors TestEBPFSynDropRejectsBoth: the
// underlying kernel maps (syndrop_cidr_v4/v6) are inherently per-direction.
func TestEBPFSynDropCIDRRejectsBoth(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"cidr": "203.0.113.0/24", "direction": "both"})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/syn-drop-cidr", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST syn-drop-cidr with direction=both: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestEBPFSynDropCIDRRejectsInvalidCIDR confirms a malformed CIDR is
// rejected via netip.ParsePrefix, not silently accepted.
func TestEBPFSynDropCIDRRejectsInvalidCIDR(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"cidr": "not-a-cidr", "direction": "egress"})
	req := httptest.NewRequest("POST", "/api/v1/ebpf/syn-drop-cidr", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST syn-drop-cidr with invalid CIDR: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
