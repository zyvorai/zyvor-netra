// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package agent

import (
	"io"
	"log/slog"
	"math/rand"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/zyvorai/netra/internal/models"
)

// The new readers must return exactly what the loops they replaced returned.
// These tests build real BPF maps of the production shapes, fill them with random
// entries, and run both implementations (the legacy ones are kept verbatim in
// legacy_readers_test.go). They need CAP_BPF, so they skip without it and run in
// the privileged CI job.

type mapShape struct {
	name       string
	key, val   uint32
	familyByte int // offset of the address-family byte in the key
}

var shapes = []mapShape{
	{"workload_flow_stats", 48, 32, 8},
	{"flow_stats", 40, 32, 0},
	{"tcp_health", 56, 136, 8},
	{"udp_flow_health", 56, 24, 8},
	{"quic_observed", 32, 24, 8},
	{"conntrack", 16, 16, 0},
}

func equivAgent(t *testing.T, fill map[string]int, tieBuckets int) *Agent {
	t.Helper()
	cg := map[uint64]models.WorkloadIdentity{}
	for i := uint64(0); i < 40; i++ {
		cg[i] = models.WorkloadIdentity{Namespace: "ns", Pod: "pod", WorkloadKind: "Deployment", WorkloadName: "w", ContainerID: "c"}
	}
	a := &Agent{
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		workloadByCgroup: cg,
		collection:       &ebpf.Collection{Maps: map[string]*ebpf.Map{}},
	}
	r := rand.New(rand.NewSource(42))
	for _, s := range shapes {
		n, ok := fill[s.name]
		if !ok {
			continue
		}
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: s.key, ValueSize: s.val, MaxEntries: 131072})
		if err != nil {
			t.Skipf("cannot create BPF maps (needs root/CAP_BPF): %v", err)
		}
		t.Cleanup(func() { _ = m.Close() })
		a.collection.Maps[s.name] = m
		for i := 0; i < n; i++ {
			k := make([]byte, s.key)
			v := make([]byte, s.val)
			r.Read(k)
			r.Read(v)
			k[s.familyByte] = []byte{4, 6, 4, 6, 0}[r.Intn(5)] // mostly IPv4/IPv6, some unknown
			k[0] = byte(i)                                     // spread the cgroup ids so enrichment hits some
			if s.name != "flow_stats" && s.name != "conntrack" {
				k[1] = 0
				for j := 2; j < 8; j++ {
					k[j] = 0
				}
			}
			if s.name == "flow_stats" {
				k[0] = []byte{4, 6, 4}[r.Intn(3)]
				k[2] = byte(r.Intn(3)) // hook: 2 is excluded from the report
			}
			// Make the entry unique: the first bytes carry the index.
			k[len(k)-1], k[len(k)-2] = byte(i), byte(i>>8)
			if tieBuckets > 0 {
				// Collapse the ranking fields onto a few distinct values.
				tie := uint64(r.Intn(tieBuckets))
				putNative(v[0:8], tie)
				if len(v) >= 16 {
					putNative(v[8:16], tie)
				}
				if len(v) >= 56 {
					putNative(v[24:32], tie)
					putNative(v[32:40], 0)
					putNative(v[48:56], 0)
				}
			}
			if err := m.Put(k, v); err != nil {
				t.Fatalf("%s put %d: %v", s.name, i, err)
			}
		}
	}
	return a
}

func putNative(b []byte, v uint64) { native.PutUint64(b, v) }

// full is enough entries to overflow every reader's cap of 1 000 several times.
var full = map[string]int{"workload_flow_stats": 9000, "flow_stats": 9000, "tcp_health": 9000, "udp_flow_health": 9000, "quic_observed": 3000, "conntrack": 5000}

func TestNewReadersReturnExactlyWhatTheLegacyLoopsReturned(t *testing.T) {
	a := equivAgent(t, full, 0)
	cases := []struct {
		name        string
		legacy, cur func() (any, error)
	}{
		{"readStats",
			func() (any, error) { return a.legacyReadStats() },
			func() (any, error) { return a.readStats() }},
		{"readTCPHealth",
			func() (any, error) { return a.legacyReadTCPHealth() },
			func() (any, error) { return a.readTCPHealth() }},
		{"readUDPFlowHealth",
			func() (any, error) { return a.legacyReadUDPFlowHealth() },
			func() (any, error) { return a.readUDPFlowHealth() }},
		{"readQUICObserved",
			func() (any, error) { return a.legacyReadQUICObserved() },
			func() (any, error) { return a.readQUICObserved() }},
	}
	for _, c := range cases {
		want, err := c.legacy()
		if err != nil {
			t.Fatalf("%s legacy: %v", c.name, err)
		}
		got, err := c.cur()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if reflect.ValueOf(want).Len() != 1000 {
			t.Fatalf("%s: the fixture should overflow the 1000 cap, legacy returned %d", c.name, reflect.ValueOf(want).Len())
		}
		if !reflect.DeepEqual(got, want) {
			gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
			for i := 0; i < gv.Len() && i < wv.Len(); i++ {
				if !reflect.DeepEqual(gv.Index(i).Interface(), wv.Index(i).Interface()) {
					t.Fatalf("%s: row %d differs\n new: %+v\n old: %+v", c.name, i, gv.Index(i).Interface(), wv.Index(i).Interface())
				}
			}
			t.Fatalf("%s: outputs differ (len %d vs %d)", c.name, gv.Len(), wv.Len())
		}
	}
}

func TestNewReadersAgreeOnRankingWhenManyEntriesTie(t *testing.T) {
	// With few distinct scores the cut falls inside a tie; the legacy sort was
	// unstable there, so only the ranking (the score sequence) is comparable.
	a := equivAgent(t, full, 7)
	oldS, err := a.legacyReadStats()
	if err != nil {
		t.Fatal(err)
	}
	newS, err := a.readStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(oldS) != len(newS) {
		t.Fatalf("%d vs %d rows", len(oldS), len(newS))
	}
	for i := range oldS {
		if oldS[i].Packets != newS[i].Packets {
			t.Fatalf("row %d: %d packets, want %d", i, newS[i].Packets, oldS[i].Packets)
		}
	}
	// And the new one is stable: reading again returns the identical rows.
	again, err := a.readStats()
	if err != nil || !reflect.DeepEqual(again, newS) {
		t.Fatalf("a re-read of an unchanged table differs (err %v)", err)
	}
}

func TestReadersBelowTheCapReturnEverything(t *testing.T) {
	a := equivAgent(t, map[string]int{"workload_flow_stats": 300, "flow_stats": 200, "tcp_health": 50, "udp_flow_health": 10, "quic_observed": 3}, 0)
	oldS, _ := a.legacyReadStats()
	newS, err := a.readStats()
	if err != nil || !reflect.DeepEqual(oldS, newS) || len(newS) == 0 {
		t.Fatalf("readStats: %d rows (old %d), err %v", len(newS), len(oldS), err)
	}
	oldH, _ := a.legacyReadTCPHealth()
	newH, err := a.readTCPHealth()
	if err != nil || len(newH) != 50 || !reflect.DeepEqual(oldH, newH) {
		t.Fatalf("readTCPHealth: %d rows, err %v", len(newH), err)
	}
}

func TestReadersFailOrDegradeLikeTheOriginals(t *testing.T) {
	a := equivAgent(t, map[string]int{"workload_flow_stats": 10}, 0)
	// flow_stats is optional for readStats, as before.
	if _, err := a.readStats(); err != nil {
		t.Fatalf("readStats without flow_stats: %v", err)
	}
	// The others are required.
	for name, fn := range map[string]func() error{
		"tcp_health":      func() error { _, e := a.readTCPHealth(); return e },
		"udp_flow_health": func() error { _, e := a.readUDPFlowHealth(); return e },
		"quic_observed":   func() error { _, e := a.readQUICObserved(); return e },
	} {
		if err := fn(); err == nil {
			t.Errorf("%s missing: want an error", name)
		}
	}
	delete(a.collection.Maps, "workload_flow_stats")
	if _, err := a.readStats(); err == nil {
		t.Error("readStats without workload_flow_stats: want an error")
	}
	// A map whose layout differs from what the agent decodes must fail loudly.
	bad, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 40, ValueSize: 32, MaxEntries: 16})
	if err != nil {
		t.Skip(err)
	}
	defer bad.Close()
	a.collection.Maps["workload_flow_stats"] = bad
	if _, err := a.readStats(); err == nil {
		t.Error("a wrong-sized workload_flow_stats must be refused, not misread")
	}
}

func TestCountEntriesMatchesTheOldCountAndIsRecorded(t *testing.T) {
	a := equivAgent(t, full, 0)
	n, err := a.countEntries("conntrack")
	if err != nil || n != 5000 {
		t.Fatalf("count = %d, err %v; want 5000", n, err)
	}
	if n, err := a.countEntries("no_such_map"); n != 0 || err != nil {
		t.Fatalf("a missing map counts as 0: %d, %v", n, err)
	}
	// Every read leaves its cost for the report.
	if _, err := a.readStats(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]models.MapScanStat{}
	for _, s := range a.mapScans() {
		seen[s.Map] = s
	}
	for _, name := range []string{"conntrack", "workload_flow_stats", "flow_stats"} {
		s, ok := seen[name]
		if !ok || s.Entries == 0 || !s.Batched || s.Syscalls == 0 {
			t.Fatalf("scan stat for %s = %+v (present %v)", name, s, ok)
		}
	}
	if s := seen["workload_flow_stats"]; s.Syscalls*20 > 2*s.Entries {
		t.Errorf("%d syscalls for %d entries: batching is not happening", s.Syscalls, s.Entries)
	}
}

func benchAgent(b *testing.B) *Agent {
	t := &testing.T{}
	_ = t
	cg := map[uint64]models.WorkloadIdentity{}
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), workloadByCgroup: cg, collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	r := rand.New(rand.NewSource(1))
	for _, s := range shapes[:2] {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: s.key, ValueSize: s.val, MaxEntries: 131072})
		if err != nil {
			b.Skipf("needs root/CAP_BPF: %v", err)
		}
		a.collection.Maps[s.name] = m
		for i := 0; i < 100000; i++ {
			k := make([]byte, s.key)
			v := make([]byte, s.val)
			r.Read(k)
			r.Read(v)
			k[s.familyByte] = 4
			if s.name == "flow_stats" {
				k[0], k[2] = 4, 0
			}
			k[len(k)-1], k[len(k)-2], k[len(k)-3] = byte(i), byte(i>>8), byte(i>>16)
			_ = m.Put(k, v)
		}
	}
	return a
}

func BenchmarkReadStatsLegacy(b *testing.B) {
	a := benchAgent(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.legacyReadStats(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadStatsNew(b *testing.B) {
	a := benchAgent(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.readStats(); err != nil {
			b.Fatal(err)
		}
	}
}
