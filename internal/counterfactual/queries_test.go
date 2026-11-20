// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"testing"
	"time"
)

func TestWhenFirstSeen(t *testing.T) {
	m := NewMemoryStore()
	w := WorkloadRef{Kind: "pod", Name: "checkout"}
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	m.Add(
		Flow{Timestamp: base.Add(2 * time.Hour), Workload: w, Direction: DirectionEgress, TLSSNI: "api.example.com"},
		Flow{Timestamp: base, Workload: w, Direction: DirectionEgress, TLSSNI: "api.example.com"},
		Flow{Timestamp: base.Add(time.Hour), Workload: w, Direction: DirectionEgress, TLSSNI: "other.example.com"},
	)

	first, ok, err := WhenFirstSeen(context.Background(), m, w, "api.example.com")
	if err != nil {
		t.Fatalf("WhenFirstSeen: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if !first.Equal(base) {
		t.Fatalf("expected first seen %v, got %v", base, first)
	}

	_, ok, err = WhenFirstSeen(context.Background(), m, w, "never-seen.example.com")
	if err != nil {
		t.Fatalf("WhenFirstSeen: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false for unseen destination")
	}
}

func TestWhenFirstSeenNilStore(t *testing.T) {
	_, _, err := WhenFirstSeen(context.Background(), nil, WorkloadRef{}, "x")
	if err == nil {
		t.Fatalf("expected error for nil store")
	}
}

func TestCompareFindsNewAndLiftedDenials(t *testing.T) {
	w := WorkloadRef{Kind: "pod", Name: "checkout"}
	flows := []Flow{
		{Timestamp: time.Now(), Direction: DirectionEgress, Workload: w, TLSSNI: "a.example.com"},
		{Timestamp: time.Now(), Direction: DirectionEgress, Workload: w, TLSSNI: "b.example.com"},
	}

	baseline := &Policy{Name: "baseline", Deny: []Rule{{Kind: RuleSNI, Names: []string{"a.example.com"}}}}
	proposed := &Policy{Name: "proposed", Deny: []Rule{{Kind: RuleSNI, Names: []string{"b.example.com"}}}}

	cmp, err := Compare(baseline, proposed, flows, Query{})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	if len(cmp.OnlyInProposed) != 1 || cmp.OnlyInProposed[0].Destination != "b.example.com" {
		t.Fatalf("expected b.example.com only in proposed, got %+v", cmp.OnlyInProposed)
	}
	if len(cmp.OnlyInBaseline) != 1 || cmp.OnlyInBaseline[0].Destination != "a.example.com" {
		t.Fatalf("expected a.example.com only in baseline, got %+v", cmp.OnlyInBaseline)
	}
}

func TestCompareIdenticalPoliciesNoDiff(t *testing.T) {
	w := WorkloadRef{Kind: "pod", Name: "checkout"}
	flows := []Flow{{Timestamp: time.Now(), Direction: DirectionEgress, Workload: w, TLSSNI: "a.example.com"}}
	p := &Policy{Name: "p", Deny: []Rule{{Kind: RuleSNI, Names: []string{"a.example.com"}}}}

	cmp, err := Compare(p, p, flows, Query{})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(cmp.OnlyInProposed) != 0 || len(cmp.OnlyInBaseline) != 0 {
		t.Fatalf("expected no diff between identical policies, got +%v -%v", cmp.OnlyInProposed, cmp.OnlyInBaseline)
	}
}
