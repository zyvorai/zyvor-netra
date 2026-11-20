// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package mapscan

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
)

// scoreOf ranks by the first 8 bytes of the value, and skips entries whose value
// byte 8 is 0xFF (the eligibility filter the flow readers use).
func scoreOf(key, val []byte) (uint64, bool) {
	if len(val) > 8 && val[8] == 0xFF {
		return 0, false
	}
	return binary.LittleEndian.Uint64(val), true
}

// reference is what the agent did before: read everything, sort everything.
func reference(t *testing.T, m *ebpf.Map, n int) []Row {
	t.Helper()
	var all []Row
	for k, v := range viaIterate(t, m) {
		if s, ok := scoreOf([]byte(k), []byte(v)); ok {
			all = append(all, Row{Key: []byte(k), Val: []byte(v), Score: s})
		}
	}
	sort.Slice(all, func(i, j int) bool { return better(&all[i], &all[j]) })
	if n < len(all) {
		all = all[:n]
	}
	return all
}

func sameRows(t *testing.T, label string, got, want []Row) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d rows, want %d", label, len(got), len(want))
	}
	for i := range want {
		if got[i].Score != want[i].Score || !bytes.Equal(got[i].Key, want[i].Key) || !bytes.Equal(got[i].Val, want[i].Val) {
			t.Fatalf("%s: row %d = score %d key %x, want score %d key %x", label, i, got[i].Score, got[i].Key, want[i].Score, want[i].Key)
		}
	}
}

// fillRandom writes n entries with random values. tieBuckets > 0 draws scores
// from that many distinct values, so most entries tie.
func fillRandom(t *testing.T, m *ebpf.Map, n, ks, vs, tieBuckets int, seed int64) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		v := make([]byte, vs)
		r.Read(v)
		if tieBuckets > 0 {
			binary.LittleEndian.PutUint64(v, uint64(r.Intn(tieBuckets)))
		}
		if err := m.Put(keyOf(uint32(i), ks), v); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTopNMatchesAFullSortForEveryN(t *testing.T) {
	m := newMap(t, ebpf.LRUHash, 48, 32, 131072)
	fillRandom(t, m, 30000, 48, 32, 0, 1)
	for _, n := range []int{1, 2, 7, 100, 1000, 29000, 30000, 50000} {
		got, st, err := TopN(m, n, scoreOf)
		if err != nil {
			t.Fatal(err)
		}
		sameRows(t, "n="+itoa(n), got, reference(t, m, n))
		if !st.Batched {
			t.Fatal("not batched")
		}
	}
}

func TestTopNIsExactAndDeterministicUnderHeavyTies(t *testing.T) {
	// 20 000 entries sharing 5 distinct scores: the cut at n falls in the middle
	// of a tie, so only a deterministic tie-break gives the same rows every time.
	m := newMap(t, ebpf.LRUHash, 16, 16, 65536)
	fillRandom(t, m, 20000, 16, 16, 5, 2)
	want := reference(t, m, 1000)
	for i := 0; i < 3; i++ {
		got, _, err := TopN(m, 1000, scoreOf)
		if err != nil {
			t.Fatal(err)
		}
		sameRows(t, "tied read "+itoa(i), got, want)
	}
}

func TestTopNSkipsIneligibleEntriesAndHandlesZeroAndEmpty(t *testing.T) {
	m := newMap(t, ebpf.LRUHash, 16, 16, 4096)
	if rows, _, err := TopN(m, 10, scoreOf); err != nil || len(rows) != 0 {
		t.Fatalf("empty map: %d rows, err %v", len(rows), err)
	}
	fillRandom(t, m, 2000, 16, 16, 0, 3)
	// Mark every third entry ineligible, and give one ineligible entry the top score.
	for i := uint32(0); i < 2000; i += 3 {
		v := make([]byte, 16)
		binary.LittleEndian.PutUint64(v, ^uint64(0))
		v[8] = 0xFF
		if err := m.Put(keyOf(i, 16), v); err != nil {
			t.Fatal(err)
		}
	}
	got, _, err := TopN(m, 50, scoreOf)
	if err != nil {
		t.Fatal(err)
	}
	sameRows(t, "filtered", got, reference(t, m, 50))
	for _, r := range got {
		if r.Val[8] == 0xFF {
			t.Fatal("an ineligible entry was returned")
		}
	}
	if rows, st, err := TopN(m, 0, scoreOf); err != nil || len(rows) != 0 || st.Entries != 2000 {
		t.Fatalf("n=0: %d rows, %+v, err %v", len(rows), st, err)
	}
}

func TestTopNRowsAreCopiesNotViewsIntoTheReusedBuffer(t *testing.T) {
	m := newMap(t, ebpf.LRUHash, 8, 8, 8192)
	fillRandom(t, m, 5000, 8, 8, 0, 4)
	got, _, err := TopN(m, 20, scoreOf)
	if err != nil {
		t.Fatal(err)
	}
	// If rows aliased the scan buffer they would all end up holding the last batch.
	keys := map[string]bool{}
	for _, r := range got {
		keys[string(r.Key)] = true
	}
	if len(keys) != 20 {
		t.Fatalf("%d distinct keys among 20 rows: the rows share memory", len(keys))
	}
	sameRows(t, "copies", got, reference(t, m, 20))
}

func BenchmarkTopN1000Of100k(b *testing.B) {
	m := benchFill(b, 100000)
	defer m.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, _, err := TopN(m, 1000, func(k, v []byte) (uint64, bool) { return binary.LittleEndian.Uint64(v), true })
		if err != nil || len(rows) != 1000 {
			b.Fatal(err, len(rows))
		}
	}
}

func itoa(n int) string {
	b := [20]byte{}
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	return string(b[i:])
}
