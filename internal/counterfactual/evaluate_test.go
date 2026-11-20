// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"testing"
	"time"
)

func TestEvaluateFlowsGroupsDenials(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	w := WorkloadRef{Kind: "pod", Namespace: "default", Name: "checkout"}

	policy := &Policy{
		Name: "deny-tracker",
		Deny: []Rule{{Kind: RuleSNI, Names: []string{"tracker.example.com"}}},
	}

	flows := []Flow{
		{Timestamp: base, Direction: DirectionEgress, Workload: w, TLSSNI: "tracker.example.com", Bytes: 100, Packets: 2},
		{Timestamp: base.Add(time.Minute), Direction: DirectionEgress, Workload: w, TLSSNI: "tracker.example.com", Bytes: 200, Packets: 3},
		{Timestamp: base.Add(2 * time.Minute), Direction: DirectionEgress, Workload: w, TLSSNI: "safe.example.com", Bytes: 50, Packets: 1},
	}

	res, err := EvaluateFlows(policy, flows, Query{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.FlowsSeen != 3 {
		t.Fatalf("expected FlowsSeen=3, got %d", res.FlowsSeen)
	}
	if len(res.Denials) != 1 {
		t.Fatalf("expected 1 denial group, got %d: %+v", len(res.Denials), res.Denials)
	}
	d := res.Denials[0]
	if d.FlowCount != 2 {
		t.Fatalf("expected FlowCount=2, got %d", d.FlowCount)
	}
	if d.TotalBytes != 300 || d.TotalPackets != 5 {
		t.Fatalf("expected aggregated bytes/packets 300/5, got %d/%d", d.TotalBytes, d.TotalPackets)
	}
	if !d.FirstSeen.Equal(base) || !d.LastSeen.Equal(base.Add(time.Minute)) {
		t.Fatalf("unexpected first/last seen: %v / %v", d.FirstSeen, d.LastSeen)
	}

	if len(res.Breakage) != 1 {
		t.Fatalf("expected 1 breakage group, got %d", len(res.Breakage))
	}
	if res.Breakage[0].Workload.Key() != w.Key() {
		t.Fatalf("unexpected breakage workload: %+v", res.Breakage[0].Workload)
	}
	if len(res.Breakage[0].Destinations) != 1 || res.Breakage[0].Destinations[0] != "tracker.example.com" {
		t.Fatalf("unexpected breakage destinations: %+v", res.Breakage[0].Destinations)
	}
}

func TestEvaluateFlowsNoDenials(t *testing.T) {
	policy := &Policy{Name: "empty"}
	flows := []Flow{{Timestamp: time.Now(), Direction: DirectionEgress}}
	res, err := EvaluateFlows(policy, flows, Query{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(res.Denials) != 0 || len(res.Breakage) != 0 {
		t.Fatalf("expected no denials/breakage, got %+v / %+v", res.Denials, res.Breakage)
	}
}

func TestEvaluatorUsesStore(t *testing.T) {
	m := NewMemoryStore()
	w := WorkloadRef{Kind: "pod", Name: "x"}
	m.Add(Flow{Timestamp: time.Now(), Direction: DirectionEgress, Workload: w, DstPort: 53, Protocol: ProtocolUDP})

	policy := &Policy{Deny: []Rule{{Kind: RulePort, Port: 53}}}
	ev := NewEvaluator(m)
	res, err := ev.Evaluate(context.Background(), policy, Query{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(res.Denials) != 1 {
		t.Fatalf("expected 1 denial, got %d", len(res.Denials))
	}
}

func TestEvaluatorNilStoreErrors(t *testing.T) {
	ev := &Evaluator{}
	_, err := ev.Evaluate(context.Background(), &Policy{}, Query{})
	if err == nil {
		t.Fatalf("expected error for nil store")
	}
}

func TestEvaluateFlowsInvalidPolicyErrors(t *testing.T) {
	policy := &Policy{Deny: []Rule{{Kind: "bogus"}}}
	_, err := EvaluateFlows(policy, nil, Query{})
	if err == nil {
		t.Fatalf("expected error for invalid policy")
	}
}
