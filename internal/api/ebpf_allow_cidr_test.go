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

// TestEBPFAllowCIDRRoundTrip guards the new CIDR-shaped allow-exception
// endpoint (mirror of the deny-side /api/v1/ebpf/cidr, but for exceptions
// evaluated before deny/CIDR/port/rate).
func TestEBPFAllowCIDRRoundTrip(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
	h := s.Handler()

	body, _ := json.Marshal(map[string]any{"cidr": "10.5.0.0/16", "direction": "both"})
	add := httptest.NewRequest("POST", "/api/v1/ebpf/allow-cidr", bytes.NewReader(body))
	add.Header.Set("Authorization", "Bearer ci-test-token")
	add.Header.Set("Content-Type", "application/json")
	addRec := httptest.NewRecorder()
	h.ServeHTTP(addRec, add)
	if addRec.Code != http.StatusOK {
		t.Fatalf("POST allow-cidr: want 200, got %d body=%s", addRec.Code, addRec.Body.String())
	}
	var cfg struct {
		AllowedCIDRs []struct {
			CIDR      string `json:"cidr"`
			Direction string `json:"direction"`
		} `json:"allowedCidrs"`
	}
	if err := json.Unmarshal(addRec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedCIDRs) != 1 || cfg.AllowedCIDRs[0].CIDR != "10.5.0.0/16" || cfg.AllowedCIDRs[0].Direction != "both" {
		t.Fatalf("allow-cidr not recorded: %+v", cfg.AllowedCIDRs)
	}

	del := httptest.NewRequest("POST", "/api/v1/ebpf/allow-cidr/delete", bytes.NewReader(body))
	del.Header.Set("Authorization", "Bearer ci-test-token")
	del.Header.Set("Content-Type", "application/json")
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("POST allow-cidr/delete: want 200, got %d body=%s", delRec.Code, delRec.Body.String())
	}
	var cfg2 struct {
		AllowedCIDRs []any `json:"allowedCidrs"`
	}
	if err := json.Unmarshal(delRec.Body.Bytes(), &cfg2); err != nil {
		t.Fatal(err)
	}
	if len(cfg2.AllowedCIDRs) != 0 {
		t.Fatalf("allow-cidr not removed: %v", cfg2.AllowedCIDRs)
	}
}
