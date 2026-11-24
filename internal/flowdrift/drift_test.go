// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package flowdrift

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func rec(ago time.Duration, wl, peer string, port uint16, bytes uint64) flowlog.Record {
	return flowlog.Record{ObservedAt: now.Add(-ago), Namespace: "shop", WorkloadName: wl, Peer: peer, Port: port, Protocol: "tcp", Direction: "egress", Bytes: bytes, Packets: 1}
}

// baseline history: cart talks to db (private) and api (public) every 30m for 5 hours.
func history() []flowlog.Record {
	var rs []flowlog.Record
	for i := 3; i <= 10; i++ {
		ago := time.Duration(i) * 30 * time.Minute
		rs = append(rs, rec(ago, "cart", "10.0.0.5", 5432, 1000), rec(ago, "cart", "198.51.100.7", 443, 5000), rec(ago, "old", "10.0.0.9", 80, 50))
	}
	return rs
}

func opts() Options {
	return Options{Now: now, Recent: time.Hour, Baseline: 6 * time.Hour, MinBaseline: time.Hour}
}

func TestDriftNewAndVanished(t *testing.T) {
	rs := history()
	// recent: cart keeps the db edge, adds a new public edge and a new private one; "old" goes quiet.
	rs = append(rs, rec(10*time.Minute, "cart", "10.0.0.5", 5432, 1000), rec(10*time.Minute, "cart", "203.0.113.99", 443, 9000), rec(5*time.Minute, "cart", "10.0.0.77", 8080, 10))
	rep := BuildDrift(rs, opts())
	if !rep.Ready || rep.Schema != Schema {
		t.Fatalf("%+v", rep)
	}
	if rep.NewTotal != 2 || rep.NewPublic != 1 || rep.Persistent != 1 {
		t.Fatalf("new=%d pub=%d persistent=%d", rep.NewTotal, rep.NewPublic, rep.Persistent)
	}
	if rep.NewEdges[0].Peer != "203.0.113.99" || !rep.NewEdges[0].Attention || rep.NewEdges[1].Attention {
		t.Fatalf("public egress must lead and carry attention: %+v", rep.NewEdges)
	}
	// 198.51.100.7 and 10.0.0.9 (old) both went quiet with >=3 observations.
	if rep.VanishedTotal != 2 {
		t.Fatalf("vanished %d: %+v", rep.VanishedTotal, rep.Vanished)
	}
	if len(rep.Workloads) == 0 || rep.Workloads[0].Workload != "cart" || rep.Workloads[0].NewPublic != 1 {
		t.Fatalf("%+v", rep.Workloads)
	}
}

func TestDriftNotReadyWithShortHistory(t *testing.T) {
	rs := []flowlog.Record{rec(70*time.Minute, "cart", "10.0.0.5", 5432, 1), rec(5*time.Minute, "cart", "203.0.113.99", 443, 1)}
	rep := BuildDrift(rs, Options{Now: now, Recent: time.Hour, Baseline: 6 * time.Hour, MinBaseline: 2 * time.Hour})
	if rep.Ready || rep.NotReady == "" || rep.NewTotal != 0 || len(rep.NewEdges) != 0 {
		t.Fatalf("a short baseline must not claim new edges: %+v", rep)
	}
	if rep := BuildDrift(nil, opts()); rep.Ready || rep.NewEdges == nil || rep.Workloads == nil {
		t.Fatalf("empty history: %+v", rep)
	}
}

func TestDriftPublicOnlyAndLimit(t *testing.T) {
	rs := history()
	for i := 0; i < 5; i++ {
		rs = append(rs, rec(time.Minute, "cart", "203.0.113."+string(rune('1'+i)), 443, uint64(100+i)))
	}
	rs = append(rs, rec(time.Minute, "cart", "10.9.9.9", 1, 1))
	o := opts()
	o.PublicOnly, o.Limit = true, 3
	rep := BuildDrift(rs, o)
	if rep.NewTotal != 5 || len(rep.NewEdges) != 3 || !rep.ListsTruncated {
		t.Fatalf("%d %d %v", rep.NewTotal, len(rep.NewEdges), rep.ListsTruncated)
	}
	for _, e := range rep.NewEdges {
		if e.PeerClass != "public" {
			t.Fatalf("%+v", e)
		}
	}
}

func TestDriftIgnoresOutOfWindowAndFuture(t *testing.T) {
	rs := history()
	rs = append(rs, rec(-time.Hour, "cart", "203.0.113.50", 1, 1), rec(30*time.Hour, "cart", "203.0.113.51", 1, 1))
	rep := BuildDrift(rs, opts())
	if rep.NewTotal != 0 {
		t.Fatalf("%+v", rep.NewEdges)
	}
}

func TestDriftOneOffBaselineNotVanished(t *testing.T) {
	rs := history()
	rs = append(rs, rec(3*time.Hour, "cart", "10.1.1.1", 1, 1))
	if rep := BuildDrift(rs, opts()); rep.VanishedTotal != 3 {
		t.Fatalf("one observation is not enough to call an edge gone: %d", rep.VanishedTotal)
	}
}

func TestPeerClass(t *testing.T) {
	for in, want := range map[string]string{"10.1.2.3": "private", "127.0.0.1": "private", "169.254.1.1": "private", "fe80::1": "private", "::ffff:10.0.0.1": "private",
		"8.8.8.8": "public", "2001:db8::1": "public", "api.example": "name", "": "name"} {
		if got := PeerClass(in); got != want {
			t.Errorf("%q: %s want %s", in, got, want)
		}
	}
}

func TestShiftSurgeAndDrop(t *testing.T) {
	var rs []flowlog.Record
	// 5 hours of baseline: a steady 100 MiB/h for "cart" and "batch"; "idle" is tiny.
	for i := 3; i <= 10; i++ {
		ago := time.Duration(i) * 30 * time.Minute
		rs = append(rs, rec(ago, "cart", "10.0.0.5", 1, 50<<20), rec(ago, "batch", "10.0.0.6", 1, 50<<20), rec(ago, "idle", "10.0.0.7", 1, 10))
	}
	// recent hour: cart sends 1 GiB (surge), batch nothing (drop), idle 1 MiB (below floor).
	rs = append(rs, rec(5*time.Minute, "cart", "10.0.0.5", 1, 1<<30), rec(5*time.Minute, "idle", "10.0.0.7", 1, 1<<20))
	rep := BuildShift(rs, ShiftOptions{Options: opts()})
	if !rep.Ready || rep.Schema != ShiftSchema || rep.Factor != DefaultFactor {
		t.Fatalf("%+v", rep)
	}
	got := map[string]string{}
	for _, s := range rep.Shifts {
		got[s.Workload] = s.Kind
	}
	if got["cart"] != "surge" || got["batch"] != "drop" || len(got) != 2 {
		t.Fatalf("%+v", rep.Shifts)
	}
	if rep.Shifts[0].Kind != "surge" {
		t.Fatalf("surges lead: %+v", rep.Shifts)
	}
}

func TestShiftNotReadyAndZeroBaseline(t *testing.T) {
	rs := []flowlog.Record{rec(5*time.Minute, "cart", "10.0.0.5", 1, 1<<30)}
	if rep := BuildShift(rs, ShiftOptions{Options: opts()}); rep.Ready || len(rep.Shifts) != 0 {
		t.Fatalf("%+v", rep)
	}
	rs = append(history(), rec(5*time.Minute, "newcomer", "10.0.0.5", 1, 1<<30))
	if rep := BuildShift(rs, ShiftOptions{Options: opts()}); func() bool {
		for _, s := range rep.Shifts {
			if s.Workload == "newcomer" {
				return true
			}
		}
		return false
	}() {
		t.Fatal("a workload with no baseline belongs to the drift report")
	}
}

func TestShiftBadFactorFallsBack(t *testing.T) {
	if rep := BuildShift(history(), ShiftOptions{Options: opts(), Factor: 0.1}); rep.Factor != DefaultFactor {
		t.Fatal(rep.Factor)
	}
}
