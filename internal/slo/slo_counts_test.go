// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package slo

import (
	"testing"
	"time"
)

var base = time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)

func newCountsRegistry(bucket time.Duration, maxObs int) *Registry {
	cfg := DefaultConfig()
	cfg.BucketWidth = bucket
	if maxObs > 0 {
		cfg.MaxObsPerSLO = maxObs
	}
	return New(cfg)
}

func TestWeightedObservationsDriveBurnRate(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "web", SLI: "http_5xx", TargetPct: 99.9, Window: 24 * time.Hour})

	// 2% errors against a 0.1% budget is a 20x burn, over the page threshold
	// of 14.4, in both the 1h and 5m windows.
	for i := 0; i < 12; i++ {
		r.Observe(Observation{Timestamp: base.Add(time.Duration(i) * 5 * time.Minute), SLI: "http_5xx", Total: 1000, Errors: 20})
	}
	alerts := r.Evaluate(base.Add(time.Hour))
	if len(alerts) != 1 || alerts[0].Severity != BurnPage {
		t.Fatalf("alerts = %+v, want one page", alerts)
	}
	if alerts[0].BurnRate < 19 || alerts[0].BurnRate > 21 {
		t.Fatalf("burn rate = %v, want ~20", alerts[0].BurnRate)
	}
}

func TestZeroTotalKeepsTheOriginalPerEventMeaning(t *testing.T) {
	if tot, e := weights(Observation{IsError: true}); tot != 1 || e != 1 {
		t.Fatalf("failed event = %d/%d", e, tot)
	}
	if tot, e := weights(Observation{}); tot != 1 || e != 0 {
		t.Fatalf("ok event = %d/%d", e, tot)
	}
	if tot, e := weights(Observation{Total: 10, Errors: 99}); tot != 10 || e != 10 {
		t.Fatalf("errors must be clamped to total, got %d/%d", e, tot)
	}
}

func TestSLISelectorKeepsSignalsApart(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "classic", TargetPct: 99})
	r.Register(Definition{Name: "http", SLI: "http_5xx", TargetPct: 99})
	r.Register(Definition{Name: "dns", SLI: "dns_failure", TargetPct: 99})

	r.Observe(Observation{Timestamp: base, IsError: true})
	r.Observe(Observation{Timestamp: base, SLI: "http_5xx", Total: 100, Errors: 50})

	got := map[string]uint64{}
	for _, s := range r.Status(base.Add(time.Minute)) {
		got[s.Definition.Name] = s.Total
	}
	if got["classic"] != 1 || got["http"] != 100 || got["dns"] != 0 {
		t.Fatalf("totals = %v: an observation leaked into an SLO for another signal", got)
	}
}

func TestNamespaceAndWorkloadFiltersStillApplyToTaggedObservations(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "checkout", SLI: "http_5xx", Namespace: "shop", Workload: "Deployment/checkout", TargetPct: 99})
	r.Observe(Observation{Timestamp: base, SLI: "http_5xx", Namespace: "shop", Workload: "Deployment/checkout", Total: 10, Errors: 1})
	r.Observe(Observation{Timestamp: base, SLI: "http_5xx", Namespace: "shop", Workload: "Deployment/cart", Total: 500, Errors: 500})
	r.Observe(Observation{Timestamp: base, SLI: "http_5xx", Namespace: "other", Workload: "Deployment/checkout", Total: 500, Errors: 500})
	st := r.Status(base.Add(time.Minute))[0]
	if st.Total != 10 || st.Errors != 1 {
		t.Fatalf("total/errors = %d/%d, want 10/1", st.Total, st.Errors)
	}
}

func TestBucketingCoalescesWithinABucket(t *testing.T) {
	r := newCountsRegistry(5*time.Minute, 0)
	r.Register(Definition{Name: "x", SLI: "s", TargetPct: 99})
	for i := 0; i < 100; i++ {
		r.Observe(Observation{Timestamp: base.Add(time.Duration(i) * time.Second), SLI: "s", Total: 10, Errors: 1})
	}
	r.mu.Lock()
	n := len(r.slos["x"].obs)
	tot, errs := r.slos["x"].obs[0].Total, r.slos["x"].obs[0].Errors
	r.mu.Unlock()
	// 100s of data fits in one 5m bucket.
	if n != 1 || tot != 1000 || errs != 100 {
		t.Fatalf("entries=%d total=%d errors=%d, want 1/1000/100", n, tot, errs)
	}
}

// The reason bucketing exists: without it, a 30-day window at one entry per
// minute would blow the default 4096-entry cap and silently cover ~68 hours.
func TestBucketedLongWindowReallyCoversTheWholeWindow(t *testing.T) {
	const window = 30 * 24 * time.Hour
	r := newCountsRegistry(5*time.Minute, 9000) // 30d/5m = 8640 buckets
	r.Register(Definition{Name: "long", SLI: "s", TargetPct: 99.9, Window: window})

	var fed uint64
	end := base.Add(window)
	for ts := base; ts.Before(end); ts = ts.Add(time.Minute) { // a sample every minute
		r.Observe(Observation{Timestamp: ts, SLI: "s", Total: 10, Errors: 0})
		fed += 10
	}
	st := r.Status(end.Add(-time.Minute))[0]
	// Allow for the trimmed first bucket only.
	if st.Total < fed-100 {
		t.Fatalf("30d window counted %d of %d events: long-window data was dropped early", st.Total, fed)
	}
	r.mu.Lock()
	n := len(r.slos["long"].obs)
	r.mu.Unlock()
	if n > 9000 || n < 8600 {
		t.Fatalf("retained %d buckets, want ~8640", n)
	}

	// And the same feed WITHOUT bucketing would have been cut off by the cap.
	plain := New(DefaultConfig())
	plain.Register(Definition{Name: "long", SLI: "s", TargetPct: 99.9, Window: window})
	for ts := base; ts.Before(end); ts = ts.Add(time.Minute) {
		plain.Observe(Observation{Timestamp: ts, SLI: "s", Total: 10})
	}
	if pst := plain.Status(end.Add(-time.Minute))[0]; pst.Total >= fed/2 {
		t.Fatalf("control failed: unbucketed feed counted %d of %d; the test is not demonstrating the problem", pst.Total, fed)
	}
}

func TestStatusDescribesEverySLOEveryTimeUnlikeEvaluate(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "b-quiet", SLI: "s", Workload: "cold", TargetPct: 99.9, Window: 24 * time.Hour})
	r.Register(Definition{Name: "a-noisy", SLI: "s", Workload: "hot", TargetPct: 99.9, Window: 24 * time.Hour})
	for i := 0; i < 12; i++ {
		ts := base.Add(time.Duration(i) * 5 * time.Minute)
		r.Observe(Observation{Timestamp: ts, SLI: "s", Workload: "hot", Total: 1000, Errors: 30})
	}
	now := base.Add(time.Hour)

	first, second := r.Status(now), r.Status(now)
	if len(first) != 2 || first[0].Definition.Name != "a-noisy" || first[1].Definition.Name != "b-quiet" {
		t.Fatalf("Status must list every SLO, ordered by name: %+v", first)
	}
	if first[0].Severity != BurnPage || second[0].Severity != BurnPage {
		t.Fatalf("a still-breaching SLO must report page on every call, got %v then %v", first[0].Severity, second[0].Severity)
	}
	if first[0].CompliancePct < 96.9 || first[0].CompliancePct > 97.1 {
		t.Fatalf("compliance = %v, want ~97", first[0].CompliancePct)
	}
	if first[0].BudgetRemaining != 0 {
		t.Fatalf("a 30x burn has spent the whole budget, remaining = %v", first[0].BudgetRemaining)
	}
	firing := 0
	for _, w := range first[0].Windows {
		if w.Firing {
			firing++
		}
	}
	if firing == 0 {
		t.Fatalf("no window reports firing: %+v", first[0].Windows)
	}

	// No data: healthy defaults, and HasData says the number is not evidence.
	q := first[1]
	if q.HasData || q.Total != 0 || q.CompliancePct != 100 || q.BudgetRemaining != 1 || q.Severity != BurnNone {
		t.Fatalf("empty SLO status = %+v", q)
	}

	// Evaluate, by contrast, reports the breach once and then stays quiet.
	if a := r.Evaluate(now); len(a) != 1 {
		t.Fatalf("first Evaluate = %d alerts, want 1", len(a))
	}
	if a := r.Evaluate(now.Add(time.Second)); len(a) != 0 {
		t.Fatalf("second Evaluate = %d alerts, want 0 (deduplicated)", len(a))
	}
}

func TestStatusRecoversWhenErrorsStop(t *testing.T) {
	r := New(DefaultConfig())
	r.Register(Definition{Name: "r", SLI: "s", TargetPct: 99.9, Window: 24 * time.Hour})
	for i := 0; i < 12; i++ {
		r.Observe(Observation{Timestamp: base.Add(time.Duration(i) * 5 * time.Minute), SLI: "s", Total: 1000, Errors: 30})
	}
	if r.Status(base.Add(time.Hour))[0].Severity != BurnPage {
		t.Fatal("expected page while errors flow")
	}
	// Two clean hours: the 5m short window empties of errors, so the page clears.
	for i := 0; i < 24; i++ {
		r.Observe(Observation{Timestamp: base.Add(time.Hour + time.Duration(i)*5*time.Minute), SLI: "s", Total: 1000})
	}
	if sev := r.Status(base.Add(3 * time.Hour))[0].Severity; sev != BurnNone {
		t.Fatalf("severity = %v after recovery, want none", sev)
	}
}
