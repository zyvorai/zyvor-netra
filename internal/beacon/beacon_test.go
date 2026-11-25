// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package beacon

import (
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func rec(at time.Time, pod, peer string, port uint16, bytes uint64) flowlog.Record {
	return flowlog.Record{ObservedAt: at, Node: "n1", Namespace: "shop", Pod: pod, WorkloadName: "api",
		Peer: peer, Port: port, Protocol: "tcp", Direction: "egress", Packets: 3, Bytes: bytes}
}

// every emits count records ending a minute before now, step apart, each moved
// by up to +/- jitter.
func every(pod, peer string, port uint16, step, jitter time.Duration, count int, bytes uint64, seed int64) []flowlog.Record {
	rng := rand.New(rand.NewSource(seed))
	var out []flowlog.Record
	at := now.Add(-time.Minute - time.Duration(count-1)*step)
	for i := 0; i < count; i++ {
		t := at.Add(time.Duration(i) * step)
		if jitter > 0 {
			t = t.Add(time.Duration(rng.Int63n(int64(2*jitter))) - jitter)
		}
		out = append(out, rec(t, pod, peer, port, bytes))
	}
	return out
}

func TestRegularCheckInIsReported(t *testing.T) {
	recs := every("api-1", "203.0.113.7", 443, time.Minute, 0, 30, 600, 1)
	recs[3].TLSSNI = "c2.example"
	recs[4].Comm = "updater"
	rep := Build(recs, Options{Now: now})
	if !rep.Ready || rep.Total != 1 || len(rep.Candidates) != 1 {
		t.Fatalf("%+v", rep)
	}
	c := rep.Candidates[0]
	if c.PeriodSeconds != 60 || c.JitterSeconds != 0 || c.Events != 30 || c.Score != 1 || c.PeerClass != "public" {
		t.Fatalf("%+v", c)
	}
	if c.Name != "c2.example" || c.Comm != "updater" || c.Pod != "api-1" || c.Node != "n1" || c.MedianBytes != 600 || c.TotalBytes != 18000 || c.Hint != "" {
		t.Fatalf("%+v", c)
	}
}

func TestJitteredCheckInIsStillReported(t *testing.T) {
	for seed := int64(1); seed <= 25; seed++ {
		rep := Build(every("api-1", "203.0.113.7", 443, time.Minute, 9*time.Second, 60, 600, seed), Options{Now: now})
		if rep.Total != 1 {
			t.Fatalf("seed %d: 15%% jitter must be found: %+v", seed, rep)
		}
		if p := rep.Candidates[0].PeriodSeconds; p < 54 || p > 66 {
			t.Fatalf("seed %d: period %v", seed, p)
		}
	}
}

func TestRandomArrivalsAreNotReported(t *testing.T) {
	for seed := int64(1); seed <= 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		var recs []flowlog.Record
		at := now.Add(-time.Minute)
		for i := 0; i < 80; i++ {
			// Poisson arrivals, mean 90s.
			at = at.Add(-time.Duration(-math.Log(1-rng.Float64()) * 90 * float64(time.Second)))
			recs = append(recs, rec(at, "api-1", "203.0.113.7", 443, uint64(100+rng.Intn(5000))))
		}
		if rep := Build(recs, Options{Now: now}); rep.Total != 0 {
			t.Fatalf("seed %d: random traffic reported: %+v", seed, rep.Candidates)
		}
	}
}

func TestContinuousTransferIsOneEventNotABeacon(t *testing.T) {
	var recs []flowlog.Record
	for i := 0; i < 2000; i++ {
		recs = append(recs, rec(now.Add(-time.Duration(i*3)*time.Second), "api-1", "203.0.113.7", 443, 9000))
	}
	rep := Build(recs, Options{Now: now})
	if !rep.Ready || rep.Total != 0 || rep.TooFew != 1 {
		t.Fatalf("%+v", rep)
	}
}

func TestMultiReportCheckInCountsOnce(t *testing.T) {
	var recs []flowlog.Record
	for i := 0; i < 20; i++ {
		at := now.Add(-time.Duration(i+1) * 2 * time.Minute)
		recs = append(recs, rec(at, "api-1", "203.0.113.7", 443, 100), rec(at.Add(3*time.Second), "api-1", "203.0.113.7", 443, 200))
	}
	rep := Build(recs, Options{Now: now})
	if rep.Total != 1 || rep.Candidates[0].Events != 20 || rep.Candidates[0].MedianBytes != 300 || rep.Candidates[0].PeriodSeconds != 120 {
		t.Fatalf("%+v", rep)
	}
}

func TestPodsAreNotInterleaved(t *testing.T) {
	// Two pods of one workload, each every minute but 25s apart: together they
	// would look irregular, apart they are two candidates.
	recs := every("api-1", "203.0.113.7", 443, time.Minute, 0, 30, 600, 1)
	for _, r := range every("api-2", "203.0.113.7", 443, time.Minute, 0, 30, 600, 1) {
		r.ObservedAt = r.ObservedAt.Add(-25 * time.Second)
		recs = append(recs, r)
	}
	rep := Build(recs, Options{Now: now})
	if rep.Total != 2 || rep.Candidates[0].Pod != "api-1" || rep.Candidates[1].Pod != "api-2" {
		t.Fatalf("%+v", rep)
	}
}

func TestPrivateIngressAndShortPeriodsAreExcluded(t *testing.T) {
	recs := every("api-1", "10.0.0.9", 8080, time.Minute, 0, 30, 600, 1)
	in := every("api-1", "203.0.113.8", 443, time.Minute, 0, 30, 600, 1)
	for i := range in {
		in[i].Direction = "ingress"
	}
	recs = append(recs, in...)
	recs = append(recs, every("api-1", "203.0.113.9", 443, 12*time.Second, 0, 200, 600, 1)...)
	empty := every("api-1", "203.0.113.10", 443, time.Minute, 0, 30, 0, 1)
	for i := range empty {
		empty[i].Packets, empty[i].Retrans = 0, 1
	}
	recs = append(recs, empty...)
	if rep := Build(recs, Options{Now: now}); rep.Total != 0 {
		t.Fatalf("%+v", rep.Candidates)
	}
	rep := Build(recs, Options{Now: now, IncludePrivate: true})
	if rep.Total != 1 || rep.Candidates[0].Peer != "10.0.0.9" || rep.Candidates[0].PeerClass != "private" {
		t.Fatalf("%+v", rep.Candidates)
	}
}

func TestSparseSeriesFailsCoverage(t *testing.T) {
	// Ten one-minute-spaced events, then silence for hours, then ten more: the
	// intervals look regular but most expected check-ins never happened.
	a := every("api-1", "203.0.113.7", 443, time.Minute, 0, 10, 600, 1)
	var recs []flowlog.Record
	for _, r := range a {
		recs = append(recs, r)
		r.ObservedAt = r.ObservedAt.Add(-5 * time.Hour)
		recs = append(recs, r)
	}
	if rep := Build(recs, Options{Now: now}); rep.Total != 0 {
		t.Fatalf("%+v", rep.Candidates)
	}
}

func TestOrderingPutsHintedAndPrivateLast(t *testing.T) {
	ntp := every("api-1", "203.0.113.1", 123, time.Minute, 0, 30, 76, 1)
	for i := range ntp {
		ntp[i].Protocol = "udp"
	}
	recs := append(ntp, every("api-1", "10.0.0.1", 443, time.Minute, 0, 30, 600, 1)...)
	recs = append(recs, every("api-1", "203.0.113.2", 443, time.Minute, 6*time.Second, 30, 600, 3)...)
	rep := Build(recs, Options{Now: now, IncludePrivate: true})
	if rep.Total != 3 || rep.Candidates[0].Peer != "203.0.113.2" || rep.Candidates[1].Peer != "10.0.0.1" || rep.Candidates[2].Hint == "" {
		t.Fatalf("%+v", rep.Candidates)
	}
	rep = Build(recs, Options{Now: now, IncludePrivate: true, Limit: 1})
	if rep.Total != 3 || len(rep.Candidates) != 1 || !rep.ListTruncated {
		t.Fatalf("%+v", rep)
	}
}

func TestNotReadyOnShortHistory(t *testing.T) {
	rep := Build(every("api-1", "203.0.113.7", 443, 30*time.Second, 0, 6, 600, 1), Options{Now: now})
	if rep.Ready || rep.NotReady == "" || len(rep.Candidates) != 0 {
		t.Fatalf("%+v", rep)
	}
	rep = Build(nil, Options{Now: now})
	if rep.Ready || rep.Candidates == nil {
		t.Fatalf("%+v", rep)
	}
}

func TestThresholdsAndWindow(t *testing.T) {
	recs := every("api-1", "203.0.113.7", 443, time.Minute, 0, 12, 600, 1)
	// Records outside the window and in the future are ignored.
	recs = append(recs, rec(now.Add(time.Hour), "api-1", "203.0.113.7", 443, 600), rec(now.Add(-48*time.Hour), "api-1", "203.0.113.7", 443, 600))
	if rep := Build(recs, Options{Now: now, MinEvents: 13}); rep.Total != 0 || rep.TooFew != 1 {
		t.Fatalf("%+v", rep)
	}
	if rep := Build(recs, Options{Now: now, MinPeriod: 5 * time.Minute, MinEvents: 6}); rep.Total != 0 {
		t.Fatalf("%+v", rep)
	}
	rep := Build(recs, Options{Now: now})
	if rep.Total != 1 || rep.Candidates[0].Events != 12 || rep.Observed != 12 {
		t.Fatalf("%+v", rep)
	}
	// Out-of-range options fall back to the defaults.
	rep = Build(recs, Options{Now: now, MinEvents: 1, MinPeriod: time.Second, MinScore: 7})
	if rep.MinEvents != DefaultMinEvents || rep.MinPeriodSeconds != 30 || rep.MinScore != DefaultMinScore {
		t.Fatalf("%+v", rep)
	}
}

func TestQuantileAndMAD(t *testing.T) {
	v := []float64{1, 2, 3, 4}
	if quantile(v, 0.5) != 2.5 || quantile(v, 1) != 4 || quantile(v, 0) != 1 || quantile(nil, 0.5) != 0 {
		t.Fatal("quantile")
	}
	if mad(v, 2.5) != 1 {
		t.Fatal("mad", mad(v, 2.5))
	}
}
