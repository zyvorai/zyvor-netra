// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

// TestDependencyGraphNilKubeDoesNotPanic guards a real bug found while
// testing this merge: dependencyGraph (called by aiSnapshot and by
// insightsDependencies/insightsRecommendations/etc.) called s.kube.ListPods
// unconditionally, with no nil-check — unlike every other s.kube consumer in
// this package. Any standalone-eBPF deployment without Kubernetes/Cilium
// access (s.kube == nil, a real supported mode per README) would panic the
// whole request instead of degrading gracefully.
func TestDependencyGraphNilKubeDoesNotPanic(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("GET", "/api/v1/insights/dependencies", nil)
	if _, err := s.dependencyGraph(r, 100); err == nil {
		t.Fatal("expected an error with nil kube client, got nil")
	}
	// aiSnapshot must degrade gracefully (skip dependency-derived fields)
	// rather than propagate the error or panic.
	if _, err := s.aiSnapshot(r); err != nil {
		t.Fatalf("aiSnapshot should not fail when kube is nil: %v", err)
	}
}

// TestAISnapshotMergesICMPTypes guards the ICMP histogram's AI-layer wiring:
// icmp_type_stats/icmp6_type_stats were populated by the kernel since 0.27.15
// but never surfaced through the Ask Netra / brief endpoints until this
// merge. v6 entries must be distinguishable from v4 ones in the flattened
// list, and the total must stay capped.
func TestAISnapshotMergesICMPTypes(t *testing.T) {
	s := &Server{store: store.New()}
	s.store.Report(models.AgentReport{
		Node: "node-a",
		ICMPTypes: []models.NamedCount{
			{Name: "echo-request", Count: 5},
			{Name: "dest-unreach", Count: 2},
		},
		ICMP6Types: []models.NamedCount{
			{Name: "echo-request", Count: 3},
		},
	})
	r := httptest.NewRequest("GET", "/api/v1/ai/brief", nil)
	snap, err := s.aiSnapshot(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.TopICMP) != 3 {
		t.Fatalf("want 3 ICMP entries, got %d: %#v", len(snap.TopICMP), snap.TopICMP)
	}
	var sawV4Echo, sawV4Unreach, sawV6Echo bool
	for _, c := range snap.TopICMP {
		switch {
		case c.Name == "echo-request" && c.Count == 5:
			sawV4Echo = true
		case c.Name == "dest-unreach" && c.Count == 2:
			sawV4Unreach = true
		case c.Name == "v6:echo-request" && c.Count == 3:
			sawV6Echo = true
		}
	}
	if !sawV4Echo || !sawV4Unreach || !sawV6Echo {
		t.Fatalf("missing expected ICMP entries: %#v", snap.TopICMP)
	}
}

// TestAISnapshotCapsICMPTypesAtEight guards the cap logic added alongside
// the merge: more than 8 combined v4/v6 entries must be truncated, not left
// to grow unbounded across many agents.
func TestAISnapshotCapsICMPTypesAtEight(t *testing.T) {
	s := &Server{store: store.New()}
	var many []models.NamedCount
	for i := 0; i < 12; i++ {
		many = append(many, models.NamedCount{Name: "icmp-x", Count: uint64(i)})
	}
	s.store.Report(models.AgentReport{Node: "node-a", ICMPTypes: many})
	r := httptest.NewRequest("GET", "/api/v1/ai/brief", nil)
	snap, err := s.aiSnapshot(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.TopICMP) != 8 {
		t.Fatalf("want TopICMP capped at 8, got %d", len(snap.TopICMP))
	}
}
