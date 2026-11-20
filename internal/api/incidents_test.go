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

func TestIncidentsTimelineMergesAuditAndDigestTransitions(t *testing.T) {
	s := &Server{store: store.New()}
	if err := s.store.AddAudit(models.AuditEvent{Actor: "alice", Action: "ebpf.mode", Target: "enforce"}); err != nil {
		t.Fatal(err)
	}
	s.store.RecordHealthSample(models.ClusterHealthSample{HealthScore: 90, Severity: "info", Fingerprint: "fp1"}, time.Now())

	r := httptest.NewRequest("GET", "/api/v1/incidents/timeline", nil)
	rec := httptest.NewRecorder()
	s.incidentsTimeline(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var tl models.Timeline
	if err := json.Unmarshal(rec.Body.Bytes(), &tl); err != nil {
		t.Fatal(err)
	}
	if len(tl.Entries) == 0 {
		t.Fatal("expected at least the audit event in the timeline")
	}
	if tl.Engine != "heuristic" {
		t.Fatalf("engine=%q, want heuristic (no AI provider configured in this test)", tl.Engine)
	}
}

func TestIncidentsTimelineRejectsInvalidSince(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("GET", "/api/v1/incidents/timeline?since=not-a-timestamp", nil)
	rec := httptest.NewRecorder()
	s.incidentsTimeline(rec, r)
	if rec.Code != 400 {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
}

func TestIncidentsDegradesGracefullyWithNilKube(t *testing.T) {
	// s.kube is nil (no Kubernetes client) — a real, supported standalone
	// deployment mode. incidents must not 502 just because the dependency
	// graph is unavailable; health/drift/rateDrift/exposure joins don't
	// need it at all.
	s := &Server{store: store.New()}
	s.store.Report(models.AgentReport{
		Node:      "n1",
		TCPHealth: []models.TCPHealthStat{{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", RemoteIP: "10.0.0.9", RemotePort: 443, SRTTUS: 800000}},
	})
	if err := s.store.SetBaseline(models.BehaviorBaseline{SchemaVersion: 1, CapturedAt: time.Now().Add(-time.Hour)}, "test"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/incidents", nil)
	rec := httptest.NewRecorder()
	s.incidents(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Items []models.IncidentCluster `json:"items"`
		Count int                      `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != len(out.Items) {
		t.Fatalf("count=%d != len(items)=%d", out.Count, len(out.Items))
	}
}
