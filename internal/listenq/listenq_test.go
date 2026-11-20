// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package listenq

import (
	"errors"
	"testing"
)

func l(port uint16, queue, max, syn uint32) Listener {
	return Listener{Family: "ipv4", Addr: "0.0.0.0", Port: port, Queue: queue, Max: max, SynRecv: syn}
}

func TestFullMeansQueueExceedsBacklogAndPctUsesTheRealCapacity(t *testing.T) {
	// The kernel refuses when queue > backlog, so a backlog of 1 holds 2.
	for _, c := range []struct {
		queue, max uint32
		full       bool
		pct        int
	}{
		{0, 1, false, 0}, {1, 1, false, 50}, {2, 1, true, 100},
		{0, 0, false, 0}, {1, 0, true, 100}, // listen(fd, 0) still holds one
		{4095, 4095, false, 99}, {4096, 4095, true, 100},
		{9, 3, true, 100}, // a racy over-count is clamped, never >100
	} {
		x := l(1, c.queue, c.max, 0)
		if x.Full() != c.full || x.Pct() != c.pct {
			t.Errorf("queue=%d max=%d: full=%v pct=%d, want full=%v pct=%d", c.queue, c.max, x.Full(), x.Pct(), c.full, c.pct)
		}
	}
}

func TestSaturatedStartsAtEightyPercentAndIncludesFull(t *testing.T) {
	if l(1, 7, 9, 0).Saturated() { // 7/10 = 70%
		t.Error("70% must not be saturated")
	}
	if !l(1, 8, 9, 0).Saturated() { // 80%
		t.Error("80% must be saturated")
	}
	if !l(1, 10, 9, 0).Saturated() || !l(1, 10, 9, 0).Full() {
		t.Error("a full queue is saturated")
	}
}

func TestBucketBoundaries(t *testing.T) {
	// backlog 3 => capacity 4: 1/4=25%, 2/4=50%, 3/4=75%, 4/4=full.
	for queue, want := range map[uint32]string{0: "empty", 1: "le_25", 2: "le_50", 3: "le_75", 4: "full"} {
		if got := Buckets[bucketOf(l(1, queue, 3, 0))]; got != want {
			t.Errorf("queue %d/4 => %q, want %q", queue, got, want)
		}
	}
	// 99% is below full: it must not be lumped with the overflowing.
	if got := Buckets[bucketOf(l(1, 99, 99, 0))]; got != "lt_100" {
		t.Errorf("99/100 => %q, want lt_100", got)
	}
}

func fake(rounds ...[]Listener) func() ([]Listener, error) {
	i := 0
	return func() ([]Listener, error) {
		r := rounds[min(i, len(rounds)-1)]
		i++
		return r, nil
	}
}

func TestHistogramAccumulatesAcrossSamples(t *testing.T) {
	s := &Sampler{Dump: fake(
		[]Listener{l(80, 0, 128, 0), l(443, 2, 1, 0)},
		[]Listener{l(80, 0, 128, 0), l(443, 1, 1, 0)},
	)}
	if _, err := s.Sample(10); err != nil {
		t.Fatal(err)
	}
	sn, err := s.Sample(10)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"empty": 2, "le_25": 0, "le_50": 1, "le_75": 0, "lt_100": 0, "full": 1}
	for b, n := range want {
		if sn.Buckets[b] != n {
			t.Errorf("bucket %s = %d, want %d (all: %v)", b, sn.Buckets[b], n, sn.Buckets)
		}
	}
	if sn.Samples != 2 || sn.Listeners != 2 {
		t.Errorf("samples=%d listeners=%d", sn.Samples, sn.Listeners)
	}
}

func TestPeakSurvivesTheQueueDrainingAndDiesWithTheListener(t *testing.T) {
	s := &Sampler{Dump: fake(
		[]Listener{l(443, 5, 9, 0)}, // pressure
		[]Listener{l(443, 0, 9, 0)}, // drained
		[]Listener{},                // listener gone
		[]Listener{l(443, 0, 9, 0)}, // a new listener on the same port
	)}
	s.Sample(10)
	sn, _ := s.Sample(10)
	if len(sn.Top) != 1 || sn.Top[0].Queue != 0 || sn.Top[0].Peak != 5 || sn.Top[0].PeakPct != 50 {
		t.Fatalf("after draining, the listener must still show its peak: %+v", sn.Top)
	}
	sn, _ = s.Sample(10)
	if sn.Listeners != 0 || len(sn.Top) != 0 {
		t.Fatalf("gone listener still reported: %+v", sn)
	}
	sn, _ = s.Sample(10)
	if len(sn.Top) != 0 {
		t.Fatalf("a new listener inherited the old one's peak: %+v", sn.Top)
	}
}

func TestTopIsDeepestFirstOmitsIdleAndIncludesHalfOpenOnly(t *testing.T) {
	s := &Sampler{Dump: fake([]Listener{
		l(1, 0, 128, 0), // idle: omitted
		l(2, 3, 9, 0),   // 30%
		l(3, 10, 9, 0),  // full
		l(4, 0, 128, 7), // nothing queued but 7 half-open: shown
		l(5, 5, 9, 0),   // 50%
	})}
	sn, _ := s.Sample(3)
	var ports []uint16
	for _, e := range sn.Top {
		ports = append(ports, e.Port)
	}
	if len(ports) != 3 || ports[0] != 3 || ports[1] != 5 || ports[2] != 2 {
		t.Fatalf("top ports = %v, want [3 5 2] (deepest first, bounded to 3)", ports)
	}
	sn, _ = s.Sample(10)
	found := false
	for _, e := range sn.Top {
		if e.Port == 1 {
			t.Error("an idle listener must not be listed")
		}
		if e.Port == 4 && e.SynRecv == 7 {
			found = true
		}
	}
	if !found {
		t.Errorf("a listener with only half-open connections must be listed: %+v", sn.Top)
	}
	if sn.Full != 1 || sn.SynRecv != 7 {
		t.Errorf("full=%d synRecv=%d", sn.Full, sn.SynRecv)
	}
}

func TestSampleFailureIsReportedAndDoesNotCorruptState(t *testing.T) {
	boom := errors.New("netlink refused")
	calls := 0
	s := &Sampler{Dump: func() ([]Listener, error) {
		calls++
		if calls == 2 {
			return nil, boom
		}
		return []Listener{l(80, 1, 1, 0)}, nil
	}}
	s.Sample(10)
	if _, err := s.Sample(10); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	sn, _ := s.Sample(10)
	if sn.Samples != 2 {
		t.Fatalf("a failed sample must not count: samples = %d, want 2", sn.Samples)
	}
}
