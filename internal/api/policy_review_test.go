// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/store"
)

func TestInsightsPolicyReviewRequiresRecommendationID(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("GET", "/api/v1/insights/policy-review", nil)
	rec := httptest.NewRecorder()
	s.insightsPolicyReview(rec, r)
	if rec.Code != 400 {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestInsightsPolicyReviewRequiresKube(t *testing.T) {
	// Unlike GET /api/v1/incidents, this endpoint genuinely cannot do
	// anything meaningful without Kubernetes (it needs live pod labels and
	// the live CiliumNetworkPolicy list to resolve which policy governs the
	// recommendation's workload), so nil s.kube is a real 502, not a
	// graceful-degradation case.
	s := &Server{store: store.New()}
	r := httptest.NewRequest("GET", "/api/v1/insights/policy-review?recommendationId=rec-abc123", nil)
	rec := httptest.NewRecorder()
	s.insightsPolicyReview(rec, r)
	if rec.Code != 502 {
		t.Fatalf("status=%d, want 502", rec.Code)
	}
}
