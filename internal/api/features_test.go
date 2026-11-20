// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListFeatures(t *testing.T) {
	t.Setenv("NETRA_DNSDETECT_ENABLED", "true")
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/features", nil)
	req.Header.Set("Authorization", "Bearer ci-test-token")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Features []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"features"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range out.Features {
		if f.ID == "dns-detect" {
			found = true
			if !f.Enabled {
				t.Fatal("expected dns-detect enabled from env")
			}
		}
	}
	if !found {
		t.Fatal("dns-detect missing from catalog response")
	}
}

func TestSetFeatureRequiresConfirm(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/features/dns-detect", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 409 {
		t.Fatalf("expected 409 without confirm, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSetFeatureUnknown(t *testing.T) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/features/nope", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Netra-Confirm-Risk", "high")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}
