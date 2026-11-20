// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/gitops"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/store"
)

func TestGitOpsStatusDisabledWithoutReconciler(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("GET", "/api/v1/policies/gitops/status", nil)
	rec := httptest.NewRecorder()
	s.gitopsStatus(rec, r)
	if rec.Code != 409 {
		t.Fatalf("status=%d, want 409 (GitOps not enabled)", rec.Code)
	}
}

func TestGitOpsResyncDisabledWithoutReconciler(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("POST", "/api/v1/policies/gitops/resync", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	s.gitopsResync(rec, r)
	if rec.Code != 409 {
		t.Fatalf("status=%d, want 409 (GitOps not enabled)", rec.Code)
	}
}

func fakeKubeForCNP(t *testing.T) *kube.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return kube.NewForTesting(srv.URL, srv.Client())
}

func TestGitOpsStatusReturnsReconcilerStatus(t *testing.T) {
	s := &Server{store: store.New(), gitops: gitops.New(slog.New(slog.DiscardHandler), fakeKubeForCNP(t), store.New(), gitops.Config{Dir: t.TempDir()})}
	r := httptest.NewRequest("GET", "/api/v1/policies/gitops/status", nil)
	rec := httptest.NewRecorder()
	s.gitopsStatus(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGitOpsResyncAppliesViaReconciler(t *testing.T) {
	s := &Server{store: store.New(), gitops: gitops.New(slog.New(slog.DiscardHandler), fakeKubeForCNP(t), store.New(), gitops.Config{Dir: t.TempDir()})}
	body := `{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"a","namespace":"prod"},"spec":{"endpointSelector":{"matchLabels":{"app":"a"}},"egress":[{"toCIDR":["10.0.0.0/24"]}]}}`
	r := httptest.NewRequest("POST", "/api/v1/policies/gitops/resync", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.gitopsResync(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var plan struct {
		Risk string `json:"risk"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Risk == "" {
		t.Fatalf("expected a computed risk in the response, got %s", rec.Body.String())
	}
}

func TestGitOpsResyncRequiresConfirmRiskHeaderForHighRisk(t *testing.T) {
	s := &Server{store: store.New(), gitops: gitops.New(slog.New(slog.DiscardHandler), fakeKubeForCNP(t), store.New(), gitops.Config{Dir: t.TempDir()})}
	body := `{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"a","namespace":"prod"},"spec":{"endpointSelector":{},"egress":[{"toCIDR":["10.0.0.0/24"]}]}}`
	r := httptest.NewRequest("POST", "/api/v1/policies/gitops/resync", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.gitopsResync(rec, r)
	if rec.Code == 200 {
		t.Fatalf("expected a critical-risk change to be rejected without X-Netra-Confirm-Risk, got 200: %s", rec.Body.String())
	}

	r2 := httptest.NewRequest("POST", "/api/v1/policies/gitops/resync", strings.NewReader(body))
	r2.Header.Set("X-Netra-Confirm-Risk", "critical")
	rec2 := httptest.NewRecorder()
	s.gitopsResync(rec2, r2)
	if rec2.Code != 200 {
		t.Fatalf("status=%d body=%s, want 200 with a matching confirm-risk header", rec2.Code, rec2.Body.String())
	}
}
