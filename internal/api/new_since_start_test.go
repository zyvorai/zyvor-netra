// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/store"
)

func TestInsightsNewSinceStartRequiresKube(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("GET", "/api/v1/insights/new-since-start", nil)
	rec := httptest.NewRecorder()
	s.insightsNewSinceStart(rec, r)
	if rec.Code != 502 {
		t.Fatalf("status=%d, want 502", rec.Code)
	}
}

func TestInsightsNewSinceStartRejectsInvalidMaxRestarts(t *testing.T) {
	s := &Server{store: store.New()}
	for _, raw := range []string{"-1", "abc"} {
		r := httptest.NewRequest("GET", "/api/v1/insights/new-since-start?maxRestarts="+raw, nil)
		rec := httptest.NewRecorder()
		s.insightsNewSinceStart(rec, r)
		if rec.Code != 400 {
			t.Fatalf("maxRestarts=%q: status=%d, want 400", raw, rec.Code)
		}
	}
}
