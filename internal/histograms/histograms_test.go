// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package histograms

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestObserveCumulative(t *testing.T) {
	s := Observe("x", []float64{1, 2, 4}, []float64{0, 1, 3, 10})
	// samples: 0→≤1, 1→≤1, 3→≤4, 10→+Inf
	// exclusive: [2, 0, 1, 1] → cumulative [2, 2, 3, 4]
	want := []uint64{2, 2, 3, 4}
	if len(s.CumulativeCounts) != len(want) {
		t.Fatalf("len=%d want %d", len(s.CumulativeCounts), len(want))
	}
	for i := range want {
		if s.CumulativeCounts[i] != want[i] {
			t.Fatalf("bucket %d = %d want %d (%v)", i, s.CumulativeCounts[i], want[i], s.CumulativeCounts)
		}
	}
	if s.Count != 4 || s.Sum != 14 {
		t.Fatalf("count=%d sum=%v", s.Count, s.Sum)
	}
}

func TestFromAgentSamples(t *testing.T) {
	r := FromAgentSamples(
		[]models.TCPHealthStat{
			{Retransmissions: 0, RTTSamples: 1, SRTTUS: 800},
			{Retransmissions: 5, RTTSamples: 2, SRTTUS: 12000},
		},
		[]models.ConnectLatencyStat{
			{Established: 2, TotalLatencyUS: 2000},
		},
		HostCounters{ListenOverflows: 3, SoftirqNETRX: 9},
	)
	if r.TCPRetransmissions.Count != 2 {
		t.Fatalf("retrans count=%d", r.TCPRetransmissions.Count)
	}
	if r.TCPSRTTUS.Count != 2 {
		t.Fatalf("srtt count=%d", r.TCPSRTTUS.Count)
	}
	if r.TCPConnectUS.Count != 1 || r.TCPConnectUS.Sum != 1000 {
		t.Fatalf("connect hist=%+v", r.TCPConnectUS)
	}
	if r.Host.ListenOverflows != 3 || r.Host.SoftirqNETRX != 9 {
		t.Fatalf("host=%+v", r.Host)
	}
}

func TestMerge(t *testing.T) {
	a := Observe("x", []float64{1, 4}, []float64{1})
	b := Observe("x", []float64{1, 4}, []float64{5})
	m := Merge(a, b)
	if m.Count != 2 {
		t.Fatalf("count=%d", m.Count)
	}
	// a: [1,1,1] b: [0,0,1] → [1,1,2]
	want := []uint64{1, 1, 2}
	for i := range want {
		if m.CumulativeCounts[i] != want[i] {
			t.Fatalf("merged %v want %v", m.CumulativeCounts, want)
		}
	}
}
