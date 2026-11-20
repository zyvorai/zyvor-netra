// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func redReport(scale uint64) *models.AgentReport {
	return &models.AgentReport{
		Stats: []models.DestinationStat{
			{Namespace: "shop", Pod: "cart-1", WorkloadKind: "Deployment", WorkloadName: "cart", Packets: 100 * scale, Bytes: 1000 * scale, Blocked: scale},
			{Namespace: "shop", Pod: "cart-2", WorkloadKind: "Deployment", WorkloadName: "cart", Packets: 100 * scale, Bytes: 1000 * scale},
			{Packets: 999 * scale}, // host traffic: no workload
		},
		TCPHealth: []models.TCPHealthStat{
			{Namespace: "shop", Pod: "cart-1", WorkloadName: "cart", Retransmissions: 2 * scale, RTTSamples: 10, SRTTUS: 2000},
			{Namespace: "shop", Pod: "cart-2", WorkloadName: "cart", RTTSamples: 30, SRTTUS: 6000},
		},
		HTTPStatus: []models.HTTPStatusStat{
			{Namespace: "shop", Pod: "cart-1", WorkloadName: "cart", Status: 200, Count: 9 * scale},
			{Namespace: "shop", Pod: "cart-1", WorkloadName: "cart", Status: 503, Count: scale},
		},
	}
}

func TestWorkloadREDAndReplay(t *testing.T) {
	var cur *models.AgentReport
	w := &WorkloadRED{Latest: func() *models.AgentReport { return cur }}
	e := NewEmitter()
	t0 := time.Unix(1_700_000_000, 0)
	run := func(at time.Time) map[string]float64 {
		e.Begin(at)
		if err := w.Collect(at, e); err != nil {
			t.Fatal(err)
		}
		out := map[string]float64{}
		for _, s := range e.Samples() {
			out[s.Series.Context+"/"+s.Series.Dimension] = s.V
			if s.Series.Labels["workload"] != "cart" || s.Series.Labels["namespace"] != "shop" {
				t.Fatalf("labels %v", s.Series.Labels)
			}
		}
		return out
	}
	cur = redReport(1)
	run(t0)
	cur = redReport(4) // three seconds later, like a real report cadence
	got := run(t0.Add(3 * time.Second))
	want := map[string]float64{
		"workload.red_rate/packets":       200, // (800-200)/3
		"workload.red_errors/blocked":     1,
		"workload.red_errors/retransmits": 2,
		"workload.red_http/errors_5xx":    1,
		"workload.red_duration/srtt":      5, // (2000*10+6000*30)/40 µs
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (all %v)", k, got[k], v, got)
		}
	}
	// Between reports the last rates repeat rather than dropping to zero.
	again := run(t0.Add(4 * time.Second))
	if again["workload.red_rate/packets"] != 200 {
		t.Fatalf("replay %v", again)
	}
	// A report that never changes stops being replayed.
	for i := 0; i < maxReplay+1; i++ {
		again = run(t0.Add(time.Duration(5+i) * time.Second))
	}
	if len(again) != 0 {
		t.Fatalf("stale report still emitted %v", again)
	}
}
