// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func TestKernelNetworkDiagnosticsUsesWindowDeltas(t *testing.T) {
	st := store.New()
	now := time.Now().UTC()
	boot := now.Add(-time.Hour)
	st.Report(apiKernelReport(now.Add(-time.Minute), boot, 100))
	st.Report(apiKernelReport(now, boot, 106))
	s := &Server{store: st, agentStaleAfter: 2 * time.Minute}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ebpf/kernel-network?window=5m", nil)
	s.ebpfKernelNetworkDiagnostics(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got models.KernelNetworkDiagnosticsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Findings != 1 || len(got.Nodes) != 1 || got.Nodes[0].Window == nil {
		t.Fatalf("unexpected response: %#v", got)
	}
	if got.Nodes[0].Window.Counters[0].Delta != 6 || got.Nodes[0].Findings[0].WindowSeconds != 60 {
		t.Fatalf("endpoint did not use interval evidence: %#v", got.Nodes[0])
	}
}

func TestKernelNetworkDiagnosticsRejectsInvalidWindow(t *testing.T) {
	s := &Server{store: store.New()}
	rec := httptest.NewRecorder()
	s.ebpfKernelNetworkDiagnostics(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ebpf/kernel-network?window=forever", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestKernelNetworkSparklineReturnsConsecutivePairs(t *testing.T) {
	st := store.New()
	now := time.Now().UTC()
	boot := now.Add(-time.Hour)
	st.Report(apiKernelReport(now.Add(-2*time.Minute), boot, 100))
	st.Report(apiKernelReport(now.Add(-time.Minute), boot, 106))
	st.Report(apiKernelReport(now, boot, 118))
	s := &Server{store: st, agentStaleAfter: 2 * time.Minute}

	rec := httptest.NewRecorder()
	s.ebpfKernelNetworkSparkline(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ebpf/kernel-network/sparkline?node=node-a&points=30", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Node    string                       `json:"node"`
		Windows []models.KernelNetworkWindow `json:"windows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Node != "node-a" || len(got.Windows) != 2 {
		t.Fatalf("unexpected response: %#v", got)
	}
	if got.Windows[0].Counters[0].Delta != 6 || got.Windows[1].Counters[0].Delta != 12 {
		t.Fatalf("unexpected per-pair deltas: %#v", got.Windows)
	}
}

func TestKernelNetworkSparklineRequiresNode(t *testing.T) {
	s := &Server{store: store.New()}
	rec := httptest.NewRecorder()
	s.ebpfKernelNetworkSparkline(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ebpf/kernel-network/sparkline", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func apiKernelReport(at, boot time.Time, receiveErrors uint64) models.AgentReport {
	return models.AgentReport{
		Node: "node-a", ObservedAt: at, AgentStartedAt: boot,
		KernelNetwork: models.KernelNetworkSnapshot{
			Tunables: []models.KernelTunable{{Name: "net.core.rmem_max", Value: "212992"}},
			Counters: []models.KernelNetworkCounter{{Name: "Udp.RcvbufErrors", Value: receiveErrors}},
		},
	}
}
