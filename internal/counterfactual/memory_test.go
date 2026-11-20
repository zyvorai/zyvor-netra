// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStoreQueryFiltersByWindowAndWorkload(t *testing.T) {
	m := NewMemoryStore()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	wa := WorkloadRef{Kind: "pod", Namespace: "default", Name: "a"}
	wb := WorkloadRef{Kind: "pod", Namespace: "default", Name: "b"}

	m.Add(
		Flow{Timestamp: base, Workload: wa},
		Flow{Timestamp: base.Add(time.Hour), Workload: wa},
		Flow{Timestamp: base.Add(2 * time.Hour), Workload: wb},
		Flow{Timestamp: base.Add(3 * time.Hour), Workload: wa},
	)
	if m.Len() != 4 {
		t.Fatalf("expected 4 flows, got %d", m.Len())
	}

	got, err := m.Query(context.Background(), Query{
		Start:    base.Add(30 * time.Minute),
		End:      base.Add(3 * time.Hour),
		Workload: wa.Key(),
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 flow in window, got %d", len(got))
	}
	if !got[0].Timestamp.Equal(base.Add(time.Hour)) {
		t.Fatalf("unexpected flow returned: %+v", got[0])
	}
}

func TestMemoryStoreQueryOrdersAscendingAndLimits(t *testing.T) {
	m := NewMemoryStore()
	base := time.Now().UTC()
	m.Add(
		Flow{Timestamp: base.Add(3 * time.Minute)},
		Flow{Timestamp: base.Add(1 * time.Minute)},
		Flow{Timestamp: base.Add(2 * time.Minute)},
	)
	got, err := m.Query(context.Background(), Query{Limit: 2})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 flows due to limit, got %d", len(got))
	}
	if !got[0].Timestamp.Before(got[1].Timestamp) {
		t.Fatalf("expected ascending order, got %v then %v", got[0].Timestamp, got[1].Timestamp)
	}
}

func TestMemoryStoreQueryEmptyWindowMeansNoBound(t *testing.T) {
	m := NewMemoryStore()
	m.Add(Flow{Timestamp: time.Unix(0, 0)}, Flow{Timestamp: time.Now()})
	got, err := m.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected all flows with zero-value window, got %d", len(got))
	}
}
