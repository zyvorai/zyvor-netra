// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

// fakeKubeListWorkloads serves GET /api/v1/pods?fieldSelector=spec.nodeName=<node>
// with a canned single-pod list while failing.Load() != 0, and a working
// list otherwise, so tests can flip a live server between success and
// transient-failure without spinning up a second httptest.Server.
func fakeKubeListWorkloads(t *testing.T, failing *atomic.Bool) *kube.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[{"metadata":{"uid":"pod-uid-1","name":"api-7d9f","namespace":"prod","labels":{}},"spec":{"nodeName":"node-1"}}]}`))
	}))
	t.Cleanup(srv.Close)
	return kube.NewForTesting(srv.URL, srv.Client())
}

func decodeEBPFConfig(t *testing.T, rec *httptest.ResponseRecorder) models.EBPFFastPathConfig {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var cfg models.EBPFFastPathConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return cfg
}

func TestEBPFConfigFallsBackToCachedWorkloadsOnFetchError(t *testing.T) {
	var failing atomic.Bool
	s := New(slog.New(slog.DiscardHandler), fakeKubeListWorkloads(t, &failing), nil, store.New())

	// First call succeeds: populates the workload inventory cache.
	r := httptest.NewRequest("GET", "/api/v1/ebpf/config?node=node-1", nil)
	rec := httptest.NewRecorder()
	s.ebpfConfig(rec, r)
	cfg := decodeEBPFConfig(t, rec)
	if len(cfg.Workloads) != 1 || cfg.Workloads[0].UID != "pod-uid-1" {
		t.Fatalf("expected the fetched workload on a successful call, got %+v", cfg.Workloads)
	}

	// Second call fails: cfg.Workloads must still carry the last-known-good
	// inventory instead of coming back empty.
	failing.Store(true)
	r2 := httptest.NewRequest("GET", "/api/v1/ebpf/config?node=node-1", nil)
	rec2 := httptest.NewRecorder()
	s.ebpfConfig(rec2, r2)
	cfg2 := decodeEBPFConfig(t, rec2)
	if len(cfg2.Workloads) != 1 || cfg2.Workloads[0].UID != "pod-uid-1" {
		t.Fatalf("expected the cached workload to survive a fetch error, got %+v", cfg2.Workloads)
	}
}

func TestEBPFConfigWorkloadsEmptyWhenNeverSucceeded(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	s := New(slog.New(slog.DiscardHandler), fakeKubeListWorkloads(t, &failing), nil, store.New())

	r := httptest.NewRequest("GET", "/api/v1/ebpf/config?node=node-1", nil)
	rec := httptest.NewRecorder()
	s.ebpfConfig(rec, r)
	cfg := decodeEBPFConfig(t, rec)
	if len(cfg.Workloads) != 0 {
		t.Fatalf("expected no workloads when the node has never had a successful fetch, got %+v", cfg.Workloads)
	}
}

func TestEBPFConfigWorkloadsEmptyWithoutNodeParam(t *testing.T) {
	var failing atomic.Bool
	s := New(slog.New(slog.DiscardHandler), fakeKubeListWorkloads(t, &failing), nil, store.New())

	r := httptest.NewRequest("GET", "/api/v1/ebpf/config", nil)
	rec := httptest.NewRecorder()
	s.ebpfConfig(rec, r)
	cfg := decodeEBPFConfig(t, rec)
	if len(cfg.Workloads) != 0 {
		t.Fatalf("expected no workload lookup without a node query param, got %+v", cfg.Workloads)
	}
}
