// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package mapscan

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
)

// These tests create real BPF maps, so they need CAP_BPF (the privileged CI job,
// or root) and skip otherwise.

func newMap(t *testing.T, typ ebpf.MapType, key, val, max uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: typ, KeySize: key, ValueSize: val, MaxEntries: max})
	if err != nil {
		t.Skipf("cannot create a %s map (needs root/CAP_BPF): %v", typ, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// keyOf/valOf build deterministic, distinguishable entries of any size.
func keyOf(i uint32, size int) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, i)
	for j := 4; j < size; j++ {
		b[j] = byte(i>>uint(j%4*8)) ^ byte(j)
	}
	return b
}

func valOf(i uint32, size int) []byte {
	b := make([]byte, size)
	var w [8]byte
	binary.LittleEndian.PutUint64(w[:], uint64(i)*7+1)
	copy(b, w[:]) // a value shorter than 8 bytes keeps only the low bytes
	for j := 8; j < size; j++ {
		b[j] = byte(i) + byte(j)
	}
	return b
}

func fill(t *testing.T, m *ebpf.Map, n, ks, vs int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := m.Put(keyOf(uint32(i), ks), valOf(uint32(i), vs)); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
}

func collect(t *testing.T, m *ebpf.Map) (map[string]string, Stats) {
	t.Helper()
	got := map[string]string{}
	dups := 0
	st, err := Scan(m, func(k, v []byte) bool {
		if _, dup := got[string(k)]; dup {
			dups++
		}
		got[string(k)] = string(v) // copies: the views are only valid during the call
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if dups != 0 {
		t.Fatalf("%d keys seen twice in a quiescent map", dups)
	}
	return got, st
}

// The reference: what the agent used until now.
func viaIterate(t *testing.T, m *ebpf.Map) map[string]string {
	t.Helper()
	out := map[string]string{}
	key := make([]byte, m.KeySize())
	val := make([]byte, m.ValueSize())
	it := m.Iterate()
	for it.Next(&key, &val) {
		out[string(key)] = string(val)
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScanMatchesIterateExactlyOnALargeLRUMap(t *testing.T) {
	// The shape of workload_flow_stats: 48-byte key, 32-byte value.
	m := newMap(t, ebpf.LRUHash, 48, 32, 131072)
	const n = 60000
	fill(t, m, n, 48, 32)

	got, st := collect(t, m)
	want := viaIterate(t, m)
	if len(got) != n || len(want) != n {
		t.Fatalf("scan saw %d, iterate saw %d, want %d", len(got), len(want), n)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("entry %x differs: scan %x, iterate %x", k, got[k], v)
		}
	}
	// And the values are the ones written, byte for byte.
	for i := uint32(0); i < 100; i++ {
		if !bytes.Equal([]byte(got[string(keyOf(i, 48))]), valOf(i, 32)) {
			t.Fatalf("entry %d has the wrong value", i)
		}
	}
	if !st.Batched || st.Entries != n {
		t.Fatalf("stats = %+v, want a batched read of %d entries", st, n)
	}
	// The point of the exercise: iterate makes 2 syscalls per entry.
	if st.Syscalls*50 > 2*n {
		t.Fatalf("%d syscalls for %d entries; batching should need about one per 1024", st.Syscalls, n)
	}
	t.Logf("%d entries in %d syscalls (Iterate would use %d)", n, st.Syscalls, 2*n)
}

func TestScanPlainHashAndOddSizes(t *testing.T) {
	for _, c := range []struct{ ks, vs int }{{4, 8}, {16, 24}, {40, 32}, {13, 5}} {
		m := newMap(t, ebpf.Hash, uint32(c.ks), uint32(c.vs), 4096)
		fill(t, m, 3000, c.ks, c.vs)
		got, st := collect(t, m)
		want := viaIterate(t, m)
		if len(got) != len(want) || len(got) != 3000 {
			t.Fatalf("key %d val %d: scan %d, iterate %d", c.ks, c.vs, len(got), len(want))
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("key %d val %d: entry differs", c.ks, c.vs)
			}
		}
		if !st.Batched {
			t.Fatalf("key %d val %d: not batched", c.ks, c.vs)
		}
	}
}

func TestScanGrowsItsBatchWhenABucketDoesNotFit(t *testing.T) {
	// A batch of one against a small hash whose buckets hold several entries
	// makes the kernel return ENOSPC; Scan must grow the buffer and finish, with
	// every entry seen exactly once.
	old := startBatch
	startBatch = 1
	defer func() { startBatch = old }()

	m := newMap(t, ebpf.Hash, 8, 8, 64)
	const n = 64
	fill(t, m, n, 8, 8)
	got, st := collect(t, m)
	if len(got) != n {
		t.Fatalf("saw %d of %d entries after growing the batch", len(got), n)
	}
	if !st.Batched {
		t.Fatal("fell back to Iterate instead of growing")
	}
}

func TestScanEmptyMapAndEarlyStop(t *testing.T) {
	m := newMap(t, ebpf.LRUHash, 16, 16, 1024)
	st, err := Scan(m, func(k, v []byte) bool { t.Fatal("an empty map produced an entry"); return true })
	if err != nil || st.Entries != 0 {
		t.Fatalf("empty: stats=%+v err=%v", st, err)
	}
	fill(t, m, 500, 16, 16)
	seen := 0
	st, err = Scan(m, func(k, v []byte) bool { seen++; return seen < 10 })
	if err != nil || seen != 10 || st.Entries != 10 {
		t.Fatalf("early stop: seen=%d stats=%+v err=%v", seen, st, err)
	}
}

func TestScanFallsBackForMapTypesWithoutBatching(t *testing.T) {
	m := newMap(t, ebpf.Array, 4, 8, 100)
	for i := uint32(0); i < 100; i++ {
		if err := m.Put(i, valOf(i, 8)); err != nil {
			t.Fatal(err)
		}
	}
	got, st := collect(t, m)
	if len(got) != 100 || st.Batched {
		t.Fatalf("array: %d entries, stats %+v; want all 100 via Iterate", len(got), st)
	}
}

// Entries change while the agent reads. Scan must not error, hang or corrupt
// what it returns, only (like Iterate) possibly miss or repeat a moving entry.
func TestScanWhileTheMapIsBeingWritten(t *testing.T) {
	m := newMap(t, ebpf.LRUHash, 16, 16, 8192)
	fill(t, m, 4000, 16, 16)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint32(0); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = m.Put(keyOf(i%6000, 16), valOf(i, 16))
		}
	}()
	for round := 0; round < 20; round++ {
		bad := 0
		_, err := Scan(m, func(k, v []byte) bool {
			// Every key ever written is keyOf(x); its first 4 bytes are x, so a
			// torn or misaligned buffer would not decode to a plausible x.
			if binary.LittleEndian.Uint32(k) >= 6000 {
				bad++
			}
			return true
		})
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if bad != 0 {
			t.Fatalf("round %d: %d keys did not decode: the buffer was misread", round, bad)
		}
	}
	close(stop)
	wg.Wait()
}

func benchFill(b *testing.B, n int) *ebpf.Map {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 48, ValueSize: 32, MaxEntries: 131072})
	if err != nil {
		b.Skipf("needs root/CAP_BPF: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := m.Put(keyOf(uint32(i), 48), valOf(uint32(i), 32)); err != nil {
			b.Fatal(err)
		}
	}
	return m
}

func BenchmarkIterate100k(b *testing.B) {
	m := benchFill(b, 100000)
	defer m.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := make([]byte, 48)
		val := make([]byte, 32)
		n := 0
		it := m.Iterate()
		for it.Next(&key, &val) {
			n++
		}
		if n < 99000 {
			b.Fatal(n)
		}
	}
}

func BenchmarkScan100k(b *testing.B) {
	m := benchFill(b, 100000)
	defer m.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		if _, err := Scan(m, func(k, v []byte) bool { n++; return true }); err != nil {
			b.Fatal(err)
		}
		if n < 99000 {
			b.Fatal(n)
		}
	}
}
