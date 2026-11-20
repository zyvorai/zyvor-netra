// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/store"
)

func TestSimulatePolicyDoesNotRequireCilium(t *testing.T) {
	// s.ciliumEnabled defaults to false and s.kube is nil (a real,
	// supported standalone mode) — simulate must still respond, not gate
	// on Cilium the way plan/apply do (it never touches Cilium/kube at
	// all, only the dependency graph and agent-reported labels).
	s := &Server{store: store.New()}
	body := `{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"eg","namespace":"prod"},"spec":{"endpointSelector":{"matchLabels":{"app":"api"}},"egress":[]}}`
	r := httptest.NewRequest("POST", "/api/v1/policies/simulate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.simulatePolicy(rec, r)
	// nil s.kube means dependencyGraph errors -> 502, not a Cilium-gate 409.
	if rec.Code != 502 {
		t.Fatalf("status=%d body=%s, want 502 (nil kube), not a Cilium-disabled gate", rec.Code, rec.Body.String())
	}
}

func TestSimulatePolicyRejectsInvalidJSON(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("POST", "/api/v1/policies/simulate", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	s.simulatePolicy(rec, r)
	if rec.Code != 502 && rec.Code != 400 {
		t.Fatalf("status=%d, want 400 or 502", rec.Code)
	}
}
