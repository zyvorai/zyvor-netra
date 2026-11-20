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

func TestNodeResourcesReturnsBuildOutput(t *testing.T) {
	st := store.New()
	st.Report(models.AgentReport{
		Node:       "n1",
		ObservedAt: time.Now().UTC(),
		NodeResources: models.NodeResourceSnapshot{
			Host: models.HostResourceSnapshot{CPUPercent: 42, CPUCores: 4},
		},
	})
	s := &Server{store: st, agentStaleAfter: 45 * time.Second}
	r := httptest.NewRequest("GET", "/api/v1/node-resources", nil)
	rec := httptest.NewRecorder()
	s.nodeResources(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body models.NodeResourcesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v, body=%s", err, rec.Body.String())
	}
	if len(body.Nodes) != 1 || body.Nodes[0].Node != "n1" {
		t.Fatalf("expected node n1 in response, got %+v", body.Nodes)
	}
	if body.Nodes[0].Host.CPUPercent != 42 {
		t.Fatalf("CPUPercent = %v, want 42", body.Nodes[0].Host.CPUPercent)
	}
}

func TestNodeResourcesLimitClamped(t *testing.T) {
	st := store.New()
	st.Report(models.AgentReport{
		Node:       "n1",
		ObservedAt: time.Now().UTC(),
		NodeResources: models.NodeResourceSnapshot{
			Workloads: []models.WorkloadResourceStat{{Pod: "a", CPUPercent: 1}, {Pod: "b", CPUPercent: 2}},
		},
	})
	s := &Server{store: st, agentStaleAfter: 45 * time.Second}
	r := httptest.NewRequest("GET", "/api/v1/node-resources?limit=1", nil)
	rec := httptest.NewRecorder()
	s.nodeResources(rec, r)
	var body models.NodeResourcesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.TopWorkloadsByCPU) != 1 {
		t.Fatalf("TopWorkloadsByCPU len = %d, want 1 (limit=1)", len(body.TopWorkloadsByCPU))
	}
}
