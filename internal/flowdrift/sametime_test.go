// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package flowdrift

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

const day = 24 * time.Hour

// daily puts bytes for wl in the middle of the matching hour of each of the
// last n days.
func daily(wl string, n int, bytes uint64) []flowlog.Record {
	var rs []flowlog.Record
	for k := 1; k <= n; k++ {
		rs = append(rs, rec(time.Duration(k)*day+30*time.Minute, wl, "10.0.0.5", 443, bytes))
	}
	return rs
}

// anchor is history old enough to cover n earlier days, plus a little traffic
// in each compared hour so no day looks like a collection gap.
func anchor(n int) []flowlog.Record {
	rs := daily("heartbeat", n, 10)
	return append(rs, rec(time.Duration(n)*day+59*time.Minute, "heartbeat", "10.0.0.5", 443, 10))
}

func sameOpts() ShiftOptions {
	return ShiftOptions{Options: Options{Now: now, Recent: time.Hour, Baseline: 6 * day, MinBaseline: time.Hour}, Mode: ModeSameTime}
}

func kinds(rep ShiftReport) map[string]Shift {
	m := map[string]Shift{}
	for _, s := range rep.Shifts {
		m[s.Workload] = s
	}
	return m
}

func TestSameTimeIgnoresADailyCycle(t *testing.T) {
	// "batch" moves 1 GiB in this hour every day and nothing otherwise: the
	// single-average baseline calls tonight a surge, the same-time one does not.
	rs := append(anchor(5), daily("batch", 5, 1<<30)...)
	rs = append(rs, rec(30*time.Minute, "batch", "10.0.0.5", 443, 1<<30))
	avg := BuildShift(rs, ShiftOptions{Options: sameOpts().Options})
	if avg.BaselineMode != ModeAverage || avg.BaselineDays != 0 || kinds(avg)["batch"].Kind != "surge" {
		t.Fatalf("%+v", avg)
	}
	rep := BuildShift(rs, sameOpts())
	if !rep.Ready || rep.BaselineMode != ModeSameTime || rep.BaselineDays != 5 || len(rep.Shifts) != 0 {
		t.Fatalf("%+v", rep)
	}
	if !strings.Contains(rep.Limitations[0], "median") {
		t.Fatal(rep.Limitations)
	}
}

func TestSameTimeSurgeDropAndUnusualTime(t *testing.T) {
	rs := append(anchor(5), daily("up", 5, 20<<20)...)
	rs = append(rs, daily("down", 5, 200<<20)...)
	// "night" is busy at another time of day only.
	rs = append(rs, rec(2*day+6*time.Hour, "night", "10.0.0.5", 443, 500<<20))
	rs = append(rs,
		rec(20*time.Minute, "up", "10.0.0.5", 443, 400<<20),
		rec(20*time.Minute, "night", "10.0.0.5", 443, 80<<20),
		rec(20*time.Minute, "newcomer", "10.0.0.5", 443, 80<<20),
	)
	rep := BuildShift(rs, sameOpts())
	got := kinds(rep)
	if len(got) != 3 {
		t.Fatalf("%+v", rep.Shifts)
	}
	if s := got["up"]; s.Kind != "surge" || s.Ratio != 20 || s.BaselineBytes != 20<<20 || s.BaselinePerHour != float64(20<<20) {
		t.Fatalf("%+v", s)
	}
	if s := got["down"]; s.Kind != "drop" || s.Ratio != 0 || s.RecentBytes != 0 {
		t.Fatalf("%+v", s)
	}
	if s := got["night"]; s.Kind != "unusual-time" || s.Ratio != 0 || s.BaselineBytes != 0 || s.RecentBytes != 80<<20 {
		t.Fatalf("%+v", s)
	}
	var order []string
	for _, s := range rep.Shifts {
		order = append(order, s.Kind)
	}
	if strings.Join(order, ",") != "surge,unusual-time,drop" {
		t.Fatal(order)
	}
}

func TestSameTimeMedianResistsOneBusyDay(t *testing.T) {
	rs := append(anchor(5), daily("api", 5, 20<<20)...)
	rs = append(rs, rec(3*day+20*time.Minute, "api", "10.0.0.5", 443, 5<<30), rec(10*time.Minute, "api", "10.0.0.5", 443, 200<<20))
	if s := kinds(BuildShift(rs, sameOpts()))["api"]; s.Kind != "surge" || s.BaselineBytes != 20<<20 {
		t.Fatalf("%+v", s)
	}
}

func TestSameTimeSkipsGapDaysAndNeedsTwo(t *testing.T) {
	// Days 1 and 4 have records; days 2 and 3 are a collection gap.
	rs := []flowlog.Record{
		rec(day+30*time.Minute, "api", "10.0.0.5", 443, 20<<20),
		rec(4*day+30*time.Minute, "api", "10.0.0.5", 443, 20<<20),
		rec(4*day+59*time.Minute, "api", "10.0.0.5", 443, 1),
		rec(10*time.Minute, "api", "10.0.0.5", 443, 20<<20),
	}
	rep := BuildShift(rs, sameOpts())
	if !rep.Ready || rep.BaselineDays != 2 || len(rep.Shifts) != 0 {
		t.Fatalf("%+v", rep)
	}
	rep = BuildShift(append(anchor(1), rec(10*time.Minute, "api", "10.0.0.5", 443, 1<<30)), sameOpts())
	if rep.Ready || !strings.Contains(rep.NotReady, "only 1 earlier day") || len(rep.Shifts) != 0 {
		t.Fatalf("%+v", rep)
	}
	o := sameOpts()
	o.Recent = 30 * time.Hour
	if rep := BuildShift(anchor(5), o); rep.Ready || rep.NotReady == "" {
		t.Fatalf("%+v", rep)
	}
	o = sameOpts()
	o.Mode = "nonsense"
	if rep := BuildShift(anchor(5), o); rep.BaselineMode != ModeAverage {
		t.Fatalf("%+v", rep)
	}
}

func TestMedianOf(t *testing.T) {
	k := wlKey{"a", "b", "egress"}
	days := []map[wlKey]uint64{{k: 10}, {}, {k: 30}, {k: 20}}
	if got := medianOf(days, k); got != 15 {
		t.Fatal(got)
	}
	if medianOf(days[:3], k) != 10 || medianOf(nil, k) != 0 {
		t.Fatal("odd or empty")
	}
}
