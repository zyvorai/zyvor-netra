// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIntelFeedAndApplyGates(t *testing.T) {
	s := testExportServer(t)
	r := httptest.NewRequest("PUT", "/api/v1/intel/feed", strings.NewReader("203.0.113.55\n"))
	rec := httptest.NewRecorder()
	s.intelFeedPut(rec, r)
	if rec.Code != 200 {
		t.Fatalf("feed put status=%d body=%s", rec.Code, rec.Body.String())
	}

	r = httptest.NewRequest("GET", "/api/v1/intel/hits", nil)
	rec = httptest.NewRecorder()
	s.intelHits(rec, r)
	if rec.Code != 200 {
		t.Fatalf("hits status=%d", rec.Code)
	}

	r = httptest.NewRequest("POST", "/api/v1/intel/apply", nil)
	rec = httptest.NewRecorder()
	s.intelApply(rec, r)
	if rec.Code != 409 {
		t.Fatalf("apply without confirm want 409 got %d", rec.Code)
	}

	r = httptest.NewRequest("POST", "/api/v1/intel/apply", nil)
	r.Header.Set("X-Netra-Confirm-Risk", "high")
	rec = httptest.NewRecorder()
	s.intelApply(rec, r)
	if rec.Code != 409 {
		t.Fatalf("apply without lease want 409 got %d body=%s", rec.Code, rec.Body.String())
	}

	if _, err := s.store.SetMode("enforce", 15*time.Minute, "test"); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("POST", "/api/v1/intel/apply", nil)
	r.Header.Set("X-Netra-Confirm-Risk", "high")
	rec = httptest.NewRecorder()
	s.intelApply(rec, r)
	if rec.Code != 200 {
		t.Fatalf("apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Applied int `json:"applied"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Applied != 1 {
		t.Fatalf("%+v body=%s", out, rec.Body.String())
	}
	cfg := s.store.Config()
	if len(cfg.BlockedIPv4) != 1 || cfg.BlockedIPv4[0] != "203.0.113.55" {
		t.Fatalf("%#v", cfg.BlockedIPv4)
	}
}

func TestAIDestinationsObserve(t *testing.T) {
	s := testExportServer(t)
	r := httptest.NewRequest("GET", "/api/v1/ebpf/ai-destinations", nil)
	rec := httptest.NewRecorder()
	s.aiDestinations(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
