// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/tlsfp"
)

func TestTLSFingerprintsAPIReturnsObservedJA3(t *testing.T) {
	d := tlsfp.NewDetector(64)
	d.Observe("ci-node", tlsfp.Fingerprint{
		JA3: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		JA4: "t13d1516h2_aaaaaaaa_bbbbbbbb",
		SNI: "example.com",
	})

	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
		tlsFP:       d,
	}
	h := s.Handler()

	req := httptest.NewRequest("GET", "/api/v1/ebpf/tls-fingerprints", nil)
	req.Header.Set("Authorization", "Bearer ci-test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Fingerprints []tlsfp.Observation `json:"fingerprints"`
		Stats        map[string]any      `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Fingerprints) != 1 || body.Fingerprints[0].JA3 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("fingerprints=%+v", body.Fingerprints)
	}
	switch v := body.Stats["uniqueJa3"].(type) {
	case float64:
		if v != 1 {
			t.Fatalf("uniqueJa3=%v", v)
		}
	case int:
		if v != 1 {
			t.Fatalf("uniqueJa3=%v", v)
		}
	default:
		t.Fatalf("uniqueJa3 type %T", body.Stats["uniqueJa3"])
	}

	req2 := httptest.NewRequest("GET", "/api/v1/ebpf/tls-fingerprints/risk", nil)
	req2.Header.Set("Authorization", "Bearer ci-test-token")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("risk status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	var risk tlsfp.RiskBoard
	if err := json.Unmarshal(rec2.Body.Bytes(), &risk); err != nil {
		t.Fatal(err)
	}
	if risk.UniqueJA3 != 1 {
		t.Fatalf("risk uniqueJa3=%d", risk.UniqueJA3)
	}
}

func TestTLSFingerprintsAPIUnauthorized(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		tlsFP:       tlsfp.NewDetector(8),
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/ebpf/tls-fingerprints", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected auth failure, got 200")
	}
}
