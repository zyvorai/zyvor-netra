// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func TestInsightsHealthTrendNoHistoryDeclinesToProject(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("GET", "/api/v1/insights/health-trend", nil)
	rec := httptest.NewRecorder()
	s.insightsHealthTrend(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out models.HealthTrend
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.TimeToBreachSeconds != nil || out.Note == "" {
		t.Fatalf("expected no projection with no recorded history, got %#v", out)
	}
}

func TestInsightsHealthTrendRejectsInvalidThreshold(t *testing.T) {
	s := &Server{store: store.New()}
	for _, raw := range []string{"-1", "100", "abc"} {
		r := httptest.NewRequest("GET", "/api/v1/insights/health-trend?threshold="+raw, nil)
		rec := httptest.NewRecorder()
		s.insightsHealthTrend(rec, r)
		if rec.Code != 400 {
			t.Fatalf("threshold=%q: status=%d, want 400", raw, rec.Code)
		}
	}
}

func TestInsightsHealthTrendUsesRecordedHistory(t *testing.T) {
	s := &Server{store: store.New()}
	t0 := time.Now().Add(-10 * time.Minute)
	for i := range 6 {
		s.store.RecordHealthSample(models.ClusterHealthSample{HealthScore: 100 - 10*i}, t0.Add(time.Duration(i)*time.Minute))
	}
	r := httptest.NewRequest("GET", "/api/v1/insights/health-trend?threshold=40", nil)
	rec := httptest.NewRecorder()
	s.insightsHealthTrend(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out models.HealthTrend
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Samples != 6 || out.BreachThreshold != 40 {
		t.Fatalf("out=%#v", out)
	}
	if out.TimeToBreachSeconds == nil {
		t.Fatalf("expected a projection for a clean declining recorded history, note=%q", out.Note)
	}
}
