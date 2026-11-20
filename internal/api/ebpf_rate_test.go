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

// TestEBPFRateAcceptsIPv6 guards against regressing the IPv4-only rejection
// that used to block IPv6 destinations even after the kernel/agent gained
// full IPv6 rate-limit support (rate_v6/rate_state_v6, decide6 apply_rate).
func TestEBPFRateAcceptsIPv6(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"destination": "2001:db8::1", "pps": 500})
	req := httptest.NewRequest("PUT", "/api/v1/ebpf/rate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT rate with IPv6 destination: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	del := httptest.NewRequest("DELETE", "/api/v1/ebpf/rate/2001:db8::1", nil)
	del.Header.Set("Authorization", "Bearer ci-test-token")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE rate with IPv6 destination: want 200, got %d body=%s", delRec.Code, delRec.Body.String())
	}
}

// TestEBPFRateAcceptsBPSOnly guards BPS being independently settable
// without PPS — a rule doesn't have to carry a packet-rate cap to carry a
// byte-rate one.
func TestEBPFRateAcceptsBPSOnly(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"destination": "10.0.0.9", "bps": 5_000_000})
	req := httptest.NewRequest("PUT", "/api/v1/ebpf/rate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT rate with bps only: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var cfg struct {
		RateLimits []struct {
			Destination string `json:"destination"`
			PPS         uint32 `json:"pps"`
			BPS         uint32 `json:"bps"`
		} `json:"rateLimits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.RateLimits) != 1 || cfg.RateLimits[0].PPS != 0 || cfg.RateLimits[0].BPS != 5_000_000 {
		t.Fatalf("unexpected rate limits: %#v", cfg.RateLimits)
	}
}

// TestEBPFRateRejectsAllZero guards the "at least one of pps/bps" rule:
// an all-zero rate rule silently has no effect and should be refused, not
// accepted as a no-op.
func TestEBPFRateRejectsAllZero(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"destination": "10.0.0.10"})
	req := httptest.NewRequest("PUT", "/api/v1/ebpf/rate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT rate with neither pps nor bps: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
