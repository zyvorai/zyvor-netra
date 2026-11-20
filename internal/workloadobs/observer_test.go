// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package workloadobs

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/slo"
)

func env(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }

func TestConfigFromEnvDefaultsAreOff(t *testing.T) {
	c, err := ConfigFromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled() || c.PromSeries || c.MaxWorkloads != 100 || c.IdleTimeout != time.Hour || c.Interval != time.Minute || len(c.SLOs) != 0 {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestConfigFromEnvAcceptsAndRejects(t *testing.T) {
	good, err := ConfigFromEnv(env(map[string]string{
		"NETRA_METRICS_WORKLOAD_LABELS": "ON", "NETRA_METRICS_WORKLOAD_MAX": "250", "NETRA_METRICS_WORKLOAD_IDLE": "30m",
		"NETRA_WORKLOAD_OBS_INTERVAL": "30s",
	}))
	if err != nil || !good.PromSeries || good.MaxWorkloads != 250 || good.IdleTimeout != 30*time.Minute || good.Interval != 30*time.Second || !good.Enabled() {
		t.Fatalf("good = %+v, err = %v", good, err)
	}
	for name, kv := range map[string]map[string]string{
		"labels garbage":     {"NETRA_METRICS_WORKLOAD_LABELS": "maybe"},
		"max zero":           {"NETRA_METRICS_WORKLOAD_MAX": "0"},
		"max too big":        {"NETRA_METRICS_WORKLOAD_MAX": "5000"},
		"max not a number":   {"NETRA_METRICS_WORKLOAD_MAX": "lots"},
		"idle too short":     {"NETRA_METRICS_WORKLOAD_IDLE": "10s"},
		"idle garbage":       {"NETRA_METRICS_WORKLOAD_IDLE": "soon"},
		"interval too short": {"NETRA_WORKLOAD_OBS_INTERVAL": "1s"},
		"interval too long":  {"NETRA_WORKLOAD_OBS_INTERVAL": "10m"},
		"slo not json":       {"NETRA_SLO_DEFINITIONS": "name=x"},
	} {
		if _, err := ConfigFromEnv(env(kv)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseDefinitions(t *testing.T) {
	defs, err := ParseDefinitions(`[
	  {"name":"checkout","namespace":"shop","workload":"Deployment/checkout","sli":"http_5xx","targetPct":99.9,"window":"30d"},
	  {"name":"dns.core","sli":"dns_failure","targetPct":99.5,"window":"720h"},
	  {"name":"net","sli":"http_5xx","targetPct":99}
	]`)
	if err != nil || len(defs) != 3 {
		t.Fatalf("defs = %+v, err = %v", defs, err)
	}
	if defs[0].Window != 30*24*time.Hour || defs[1].Window != 720*time.Hour || defs[2].Window != 30*24*time.Hour {
		t.Fatalf("windows = %v %v %v", defs[0].Window, defs[1].Window, defs[2].Window)
	}
	if defs[0].SLI != "http_5xx" || defs[0].Namespace != "shop" || defs[0].Workload != "Deployment/checkout" {
		t.Fatalf("def0 = %+v", defs[0])
	}
	if d, err := ParseDefinitions("  "); d != nil || err != nil {
		t.Fatalf("blank input = %v, %v", d, err)
	}

	ok := `"sli":"http_5xx","targetPct":99.9`
	bad := map[string]string{
		"not an array":      `{"name":"x"}`,
		"empty name":        `[{"name":"",` + ok + `}]`,
		"name with a quote": `[{"name":"a\"b",` + ok + `}]`,
		"name with a space": `[{"name":"a b",` + ok + `}]`,
		"duplicate":         `[{"name":"a",` + ok + `},{"name":"a",` + ok + `}]`,
		"no sli":            `[{"name":"a","targetPct":99.9}]`,
		"unknown sli":       `[{"name":"a","sli":"latency","targetPct":99.9}]`,
		"tcp_retransmit is biased by construction and is not offered": `[{"name":"a","sli":"tcp_retransmit","targetPct":99.9}]`,
		"target zero":      `[{"name":"a","sli":"http_5xx","targetPct":0}]`,
		"target 100":       `[{"name":"a","sli":"http_5xx","targetPct":100}]`,
		"target below 50":  `[{"name":"a","sli":"http_5xx","targetPct":10}]`,
		"window too short": `[{"name":"a",` + ok + `,"window":"30m"}]`,
		"window too long":  `[{"name":"a",` + ok + `,"window":"91d"}]`,
		"window garbage":   `[{"name":"a",` + ok + `,"window":"forever"}]`,
		"window zero days": `[{"name":"a",` + ok + `,"window":"0d"}]`,
	}
	for name, raw := range bad {
		if _, err := ParseDefinitions(raw); err == nil {
			t.Errorf("%s: expected an error (a bad SLO must not be silently defaulted)", name)
		}
	}

	var many []string
	for i := range maxSLOs + 1 {
		many = append(many, `{"name":"s`+strings.Repeat("x", 1)+string(rune('a'+i%26))+string(rune('a'+i/26))+`",`+ok+`}`)
	}
	if _, err := ParseDefinitions("[" + strings.Join(many, ",") + "]"); err == nil {
		t.Error("more than the SLO limit must be rejected")
	}
}

func httpAgent(node string, ok, e5xx uint64) models.AgentStatus {
	return agent(node, func(r *models.AgentReport) {
		r.HTTPStatus = []models.HTTPStatusStat{
			{CgroupID: 1, Status: 200, Count: ok, Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "checkout"},
			{CgroupID: 1, Status: 503, Count: e5xx, Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "checkout"},
		}
	})
}

func newObs(t *testing.T, defs string) *Observer {
	t.Helper()
	d, err := ParseDefinitions(defs)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewObserver(Config{PromSeries: true, MaxWorkloads: 10, SLOs: d})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

const checkoutSLO = `[{"name":"checkout","namespace":"shop","workload":"Deployment/checkout","sli":"http_5xx","targetPct":99.9,"window":"7d"}]`

// The full SLO lifecycle, driven by cumulative agent counters the way real
// reports arrive: healthy, then burning (one audit event, not one per tick),
// then recovered (an event Evaluate() alone would never produce).
func TestSLOBurnFiresOnceThenRecovers(t *testing.T) {
	o := newObs(t, checkoutSLO)
	var (
		mu     sync.Mutex
		events []models.AuditEvent
	)
	audit := func(e models.AuditEvent) { mu.Lock(); events = append(events, e); mu.Unlock() }
	now := t0
	var ok, bad uint64
	tick := func(dOK, dBad uint64) {
		ok += dOK
		bad += dBad
		now = now.Add(5 * time.Minute)
		o.Tick([]models.AgentStatus{httpAgent("n1", ok, bad)}, now, audit)
	}

	tick(0, 0) // baseline
	for range 6 {
		tick(1000, 0)
	}
	if st := o.SLOStatus(now)[0]; st.Severity != slo.BurnNone || !st.HasData || st.Total != 6000 {
		t.Fatalf("healthy phase status = %+v", st)
	}
	if len(events) != 0 {
		t.Fatalf("healthy traffic raised %d audit events", len(events))
	}

	for range 14 { // 3% errors against a 0.1% budget: a 30x burn
		tick(970, 30)
	}
	st := o.SLOStatus(now)[0]
	if st.Severity != slo.BurnPage {
		t.Fatalf("severity = %v, want page; status = %+v", st.Severity, st)
	}
	// A burn escalates none -> ticket -> page: two transitions, two events, in
	// that order, and nothing more while it merely continues.
	mu.Lock()
	var sevs []string
	for _, e := range events {
		if e.Action == "slo.burn" && e.Target == "checkout" && e.Actor == "slo" {
			sevs = append(sevs, e.Details["severity"].(string))
		}
	}
	mu.Unlock()
	if len(sevs) != 2 || sevs[0] != "ticket" || sevs[1] != "page" {
		t.Fatalf("slo.burn severities = %v, want [ticket page]: %+v", sevs, events)
	}
	mu.Lock()
	n := len(events)
	mu.Unlock()
	for range 5 {
		tick(970, 30) // the burn goes on
	}
	mu.Lock()
	if len(events) != n {
		t.Fatalf("a continuing burn raised %d more audit events, want 0", len(events)-n)
	}
	mu.Unlock()

	for range 100 { // > 8h of clean traffic clears even the 6h short window
		tick(1000, 0)
	}
	if sev := o.SLOStatus(now)[0].Severity; sev != slo.BurnNone {
		t.Fatalf("severity = %v after recovery, want none", sev)
	}
	mu.Lock()
	defer mu.Unlock()
	last := events[len(events)-1]
	if last.Action != "slo.recovered" || last.Target != "checkout" {
		t.Fatalf("last audit event = %+v, want slo.recovered", last)
	}
}

func TestSLOFiltersToItsOwnWorkload(t *testing.T) {
	o := newObs(t, checkoutSLO)
	other := func(ok, bad uint64) models.AgentStatus {
		return agent("n1", func(r *models.AgentReport) {
			r.HTTPStatus = []models.HTTPStatusStat{
				{CgroupID: 2, Status: 200, Count: ok, Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "cart"},
				{CgroupID: 2, Status: 500, Count: bad, Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "cart"},
			}
		})
	}
	now := t0
	o.Tick([]models.AgentStatus{other(0, 0)}, now, nil)
	for i := 1; i <= 20; i++ {
		now = now.Add(5 * time.Minute)
		o.Tick([]models.AgentStatus{other(uint64(i*100), uint64(i*100))}, now, nil) // cart is on fire
	}
	if st := o.SLOStatus(now)[0]; st.HasData || st.Severity != slo.BurnNone {
		t.Fatalf("checkout's SLO was affected by another workload's errors: %+v", st)
	}
}

func TestNoSLOsMeansNoRegistryWorkAndNilAuditIsFine(t *testing.T) {
	o, err := NewObserver(Config{PromSeries: true})
	if err != nil {
		t.Fatal(err)
	}
	if o.HasSLOs() {
		t.Fatal("HasSLOs")
	}
	o.Tick([]models.AgentStatus{httpAgent("n1", 1, 0)}, t0, nil)
	o.Tick([]models.AgentStatus{httpAgent("n1", 9, 3)}, t0.Add(time.Minute), nil)
	if len(o.SLOStatus(t0)) != 0 {
		t.Fatal("no SLOs were defined")
	}
	if n, ok := find(o.Snapshot(), "shop", "Deployment/checkout"); !ok || n.V[HTTPResponses] != 11 {
		t.Fatalf("workload series must still accumulate without SLOs: %+v ok=%v", n, ok)
	}
}

func TestTickClampsBackwardsTimeSoTheRegistryStaysOrdered(t *testing.T) {
	o := newObs(t, checkoutSLO)
	o.Tick([]models.AgentStatus{httpAgent("n1", 0, 0)}, t0.Add(10*time.Minute), nil)
	o.Tick([]models.AgentStatus{httpAgent("n1", 100, 0)}, t0.Add(15*time.Minute), nil)
	// A clock step backwards must not corrupt window scans.
	o.Tick([]models.AgentStatus{httpAgent("n1", 200, 0)}, t0, nil)
	if st := o.SLOStatus(t0.Add(16 * time.Minute))[0]; st.Total != 200 {
		t.Fatalf("total = %d, want 200 (both ticks counted despite the clock step)", st.Total)
	}
}

func TestNewObserverSizesTheRingForTheLongestWindow(t *testing.T) {
	d, _ := ParseDefinitions(`[{"name":"long","sli":"http_5xx","targetPct":99.9,"window":"90d"}]`)
	o, err := NewObserver(Config{SLOs: d})
	if err != nil {
		t.Fatal(err)
	}
	// 90d / 5m = 25920 buckets; the package default cap of 4096 would cut it to ~14h.
	if got := o.reg.Config().MaxObsPerSLO; got < 25920 {
		t.Fatalf("MaxObsPerSLO = %d, want at least 25920 for a 90d window", got)
	}
	if o.reg.Config().BucketWidth != observationBucket {
		t.Fatalf("BucketWidth = %v", o.reg.Config().BucketWidth)
	}
}

func TestRunTicksImmediatelyThenOnIntervalUntilCancelled(t *testing.T) {
	o, err := NewObserver(Config{Interval: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	o.cfg.Interval = 20 * time.Millisecond // test-only: faster than the validated minimum
	var fetches atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		o.Run(ctx, func() []models.AgentStatus { fetches.Add(1); return nil }, nil)
		close(done)
	}()
	deadline := time.After(2 * time.Second)
	for fetches.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d fetches", fetches.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	after := fetches.Load()
	time.Sleep(80 * time.Millisecond)
	if fetches.Load() != after {
		t.Fatal("Run kept ticking after cancel")
	}
}

func TestSnapshotAndStatusAreSafeAlongsideTick(t *testing.T) {
	o := newObs(t, checkoutSLO)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 200 {
			o.Tick([]models.AgentStatus{httpAgent("n1", uint64(i*10), uint64(i))}, t0.Add(time.Duration(i)*time.Minute), func(models.AuditEvent) {})
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			_ = o.Snapshot()
			_ = o.SLOStatus(t0.Add(time.Hour))
		}
	}()
	wg.Wait()
}

// Helm --set renders 99.9 as the string "99.9".
func TestTargetPctAcceptsANumericStringFromHelmSet(t *testing.T) {
	defs, err := ParseDefinitions(`[{"name":"a","sli":"http_5xx","targetPct":"99.9"},{"name":"b","sli":"dns_failure","targetPct":99.5}]`)
	if err != nil || len(defs) != 2 || defs[0].TargetPct != 99.9 || defs[1].TargetPct != 99.5 {
		t.Fatalf("defs = %+v, err = %v", defs, err)
	}
	for _, bad := range []string{`"abc"`, `"99.9.9"`, `null`, `""`} {
		if _, err := ParseDefinitions(`[{"name":"a","sli":"http_5xx","targetPct":` + bad + `}]`); err == nil {
			t.Errorf("targetPct %s should be rejected", bad)
		}
	}
}
