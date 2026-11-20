// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

// Package mapscan reads every entry of a BPF hash map cheaply.
//
// The agent reads several large LRU hash maps (up to 131 072 entries each) on
// every report. ebpf.Map.Iterate costs two syscalls per entry (get-next-key,
// then lookup) and decodes into a fresh value each time; on a busy node the
// agent spent about two cores in those loops. BPF_MAP_LOOKUP_BATCH returns many
// entries per syscall (one per ~1 000), and Scan hands the caller views into the
// batch buffer so nothing is allocated per entry.
package mapscan

import (
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// startBatch is the first batch size. A hash bucket holding more entries than the
// batch makes the kernel return ENOSPC, in which case the batch is grown. It is a
// variable only so a test can force that path.
var startBatch = 1024

const maxBatch = 32768

// Stats describes one Scan, so callers can report what a read cost.
type Stats struct {
	Entries  int  // entries visited
	Syscalls int  // bpf() calls made (batched: ~Entries/1024; fallback: ~2*Entries)
	Batched  bool // false when the kernel refused batching and Iterate was used
}

// Scan calls fn for every entry of m until fn returns false. key and val are
// views into a reused buffer: valid only during the call, never to be retained
// or modified. Like Iterate, it is not atomic: entries changing while it runs may
// be missed or seen twice (the agent reads cumulative counters, so a repeat is
// harmless).
//
// Only plain hash and LRU hash maps are read in batches; anything else, and any
// kernel that lacks batch operations, falls back to Iterate.
func Scan(m *ebpf.Map, fn func(key, val []byte) bool) (Stats, error) {
	if typ := m.Type(); typ == ebpf.Hash || typ == ebpf.LRUHash {
		st, err := scanBatched(m, fn)
		if err == nil {
			return st, nil
		}
		if !errors.Is(err, errBatchUnsupported) {
			return st, err
		}
	}
	return scanIterate(m, fn)
}

var errBatchUnsupported = errors.New("batch lookup unsupported")

// arrayBuf makes a []T with n elements where T is a [size]byte, which is the
// shape BatchLookup needs for a key or value of that size, plus a flat byte view
// over the same memory.
func arrayBuf(size, n int) (slice any, flat []byte) {
	v := reflect.MakeSlice(reflect.SliceOf(reflect.ArrayOf(size, reflect.TypeOf(byte(0)))), n, n)
	return v.Interface(), unsafe.Slice((*byte)(unsafe.Pointer(v.Pointer())), n*size)
}

func scanBatched(m *ebpf.Map, fn func(key, val []byte) bool) (Stats, error) {
	ks, vs := int(m.KeySize()), int(m.ValueSize())
	if ks == 0 || vs == 0 {
		return Stats{}, errBatchUnsupported
	}
	st := Stats{Batched: true}
	batch := startBatch
	keys, kflat := arrayBuf(ks, batch)
	vals, vflat := arrayBuf(vs, batch)
	var cursor ebpf.MapBatchCursor
	for {
		n, err := m.BatchLookup(&cursor, keys, vals, nil)
		st.Syscalls++
		for i := 0; i < n; i++ {
			st.Entries++
			if !fn(kflat[i*ks:(i+1)*ks], vflat[i*vs:(i+1)*vs]) {
				return st, nil
			}
		}
		switch {
		case err == nil:
			// More to read: the cursor has advanced.
		case errors.Is(err, ebpf.ErrKeyNotExist):
			return st, nil // the normal end of the map
		case errors.Is(err, unix.ENOSPC):
			// A bucket did not fit the batch, and nothing was consumed: retry the
			// same cursor with a larger buffer.
			if batch >= maxBatch {
				return st, fmt.Errorf("map batch lookup: a bucket exceeds %d entries: %w", maxBatch, err)
			}
			batch *= 2
			keys, kflat = arrayBuf(ks, batch)
			vals, vflat = arrayBuf(vs, batch)
		case st.Syscalls == 1 && n == 0 && isUnsupported(err):
			return st, errBatchUnsupported
		default:
			return st, err
		}
	}
}

// isUnsupported reports the errors a kernel without batch operations (before
// 5.6) or without them for this map type returns.
func isUnsupported(err error) bool {
	return errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP)
}

func scanIterate(m *ebpf.Map, fn func(key, val []byte) bool) (Stats, error) {
	st := Stats{}
	key := make([]byte, m.KeySize())
	val := make([]byte, m.ValueSize())
	it := m.Iterate()
	for it.Next(&key, &val) {
		st.Entries++
		st.Syscalls += 2
		if !fn(key, val) {
			return st, nil
		}
	}
	return st, it.Err()
}
