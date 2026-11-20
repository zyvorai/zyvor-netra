// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package slo

import (
	"sync"
	"testing"
	"time"
)

func TestNoBurnOnHealthyTraffic(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "checkout", TargetPct: 99.9, Window: 30 * 24 * time.Hour})
	now := time.Now()
	const n = 10000
	for i := 0; i < n; i++ {
		// Observe requires non-decreasing timestamps (see its doc
		// comment) — insert oldest-first, ending at "now".
		r.Observe(Observation{
			Timestamp: now.Add(-time.Duration(n-1-i) * time.Second),
			Namespace: "payments", Workload: "checkout",
			Latency: 50 * time.Millisecond,
		})
	}
	alerts := r.Evaluate(now)
	if len(alerts) != 0 {
		t.Fatalf("unexpected alerts on healthy traffic: %+v", alerts)
	}
}

func TestPageBurnOnMassiveErrors(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "checkout", TargetPct: 99.9, Window: 30 * 24 * time.Hour})
	now := time.Now()
	// Fill 1h of traffic with 50% errors, oldest-first (see Observe's
	// non-decreasing-timestamp requirement).
	const n = 3600
	for i := 0; i < n; i++ {
		err := i%2 == 0
		r.Observe(Observation{
			Timestamp: now.Add(-time.Duration(n-1-i) * time.Second),
			Namespace: "payments", Workload: "checkout",
			IsError: err,
		})
	}
	alerts := r.Evaluate(now)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].Severity != BurnPage {
		t.Fatalf("severity = %v, want page", alerts[0].Severity)
	}
	if alerts[0].BurnRate < 14.4 {
		t.Fatalf("burn rate = %v, want >= 14.4", alerts[0].BurnRate)
	}
}

func TestTicketBurnOnLowErrors(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "search", TargetPct: 99.9, Window: 30 * 24 * time.Hour})
	now := time.Now()
	// 6h of traffic, ~0.5% errors -> burn rate ~5x budget. Oldest-first.
	const n = 6 * 3600
	for i := 0; i < n; i++ {
		err := i%200 == 0
		r.Observe(Observation{
			Timestamp: now.Add(-time.Duration(n-1-i) * time.Second),
			Namespace: "default", Workload: "search",
			IsError: err,
		})
	}
	alerts := r.Evaluate(now)
	if len(alerts) == 0 {
		t.Fatal("expected ticket alert")
	}
	if alerts[0].Severity != BurnTicket {
		t.Fatalf("severity = %v, want ticket", alerts[0].Severity)
	}
}

func TestSuppressionOfDuplicates(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SweepEvery = 30 * time.Second
	r := New(cfg)
	r.Register(Definition{Name: "x", TargetPct: 99.9, Window: 24 * time.Hour})
	now := time.Now()
	const n = 3600
	for i := 0; i < n; i++ {
		r.Observe(Observation{
			Timestamp: now.Add(-time.Duration(n-1-i) * time.Second),
			IsError:   true,
		})
	}
	a1 := r.Evaluate(now)
	a2 := r.Evaluate(now.Add(1 * time.Second))
	if len(a1) != 1 || len(a2) != 0 {
		t.Fatalf("expected dedup: a1=%d a2=%d", len(a1), len(a2))
	}
}

func TestBudgetRemaining(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "x", TargetPct: 99.0, Window: 1 * time.Hour})
	now := time.Now()
	// 99% errors = way over budget. Oldest-first (index 0 is the error
	// run; the single healthy sample lands last, closest to "now").
	const n = 100
	for i := 0; i < n; i++ {
		r.Observe(Observation{
			Timestamp: now.Add(-time.Duration(n-1-i) * time.Second),
			IsError:   i < 99,
		})
	}
	alerts := r.Evaluate(now)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].BudgetRemaining > 0.01 {
		t.Fatalf("budget remaining = %v, want near 0", alerts[0].BudgetRemaining)
	}
}

func TestConcurrentObserve(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "x", TargetPct: 99.9, Window: time.Hour})
	var wg sync.WaitGroup
	now := time.Now()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				r.Observe(Observation{Timestamp: now, IsError: i%10 == 0})
			}
		}()
	}
	wg.Wait()
	_ = r.Evaluate(now)
}

func TestRegisterRefusesBeyondMaxSLOs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSLOs = 2
	r := New(cfg)
	r.Register(Definition{Name: "a", TargetPct: 99.9, Window: time.Hour})
	r.Register(Definition{Name: "b", TargetPct: 99.9, Window: time.Hour})
	r.Register(Definition{Name: "c", TargetPct: 99.9, Window: time.Hour})
	r.mu.Lock()
	got := len(r.slos)
	r.mu.Unlock()
	if got != 2 {
		t.Fatalf("registered SLOs = %d, want 2 (MaxSLOs cap)", got)
	}
}

func TestObserveTrimsByWindowAndCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxObsPerSLO = 10
	r := New(cfg)
	r.Register(Definition{Name: "x", TargetPct: 99.9, Window: time.Minute})
	now := time.Now()
	// 5 observations well outside the 1-minute window.
	for i := 0; i < 5; i++ {
		r.Observe(Observation{Timestamp: now.Add(-time.Hour), IsError: false})
	}
	// 20 observations inside the window, exceeding MaxObsPerSLO. Inserted
	// oldest-first per Observe's non-decreasing-timestamp requirement.
	for i := 0; i < 20; i++ {
		r.Observe(Observation{Timestamp: now.Add(-time.Duration(19-i) * time.Second), IsError: false})
	}
	r.mu.Lock()
	n := len(r.slos["x"].obs)
	r.mu.Unlock()
	if n > cfg.MaxObsPerSLO {
		t.Fatalf("obs retained = %d, want <= %d (MaxObsPerSLO)", n, cfg.MaxObsPerSLO)
	}
}

func TestObserveOnlyMatchesScopedSLO(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "checkout", Namespace: "payments", Workload: "checkout", TargetPct: 99.9, Window: time.Hour})
	now := time.Now()
	r.Observe(Observation{Timestamp: now, Namespace: "other", Workload: "other", IsError: true})
	r.mu.Lock()
	n := len(r.slos["checkout"].obs)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("observation from an unrelated namespace/workload matched the SLO: %d obs", n)
	}
}
