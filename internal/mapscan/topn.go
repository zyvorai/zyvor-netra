// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package mapscan

import (
	"bytes"
	"sort"

	"github.com/cilium/ebpf"
)

// Row is one map entry that made it into a top-N: private copies of the raw key
// and value bytes, and the score it was ranked by.
type Row struct {
	Key, Val []byte
	Score    uint64
}

// better orders rows best-first: higher score, then the smaller key. The key
// tie-break makes the selection deterministic, so two reads of an unchanged map
// return the same rows in the same order.
func better(a, b *Row) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return bytes.Compare(a.Key, b.Key) < 0
}

// TopN scans m and returns the n best entries, best first, without decoding,
// allocating, or formatting the rest. score returns the rank of an entry and
// whether it is eligible at all; an ineligible entry is skipped.
//
// The agent used to decode every entry of a 131 072-entry table (two IP strings
// and a struct each), sort them all, then keep 1 000. This does one pass over raw
// bytes, keeps a bounded min-heap, and copies only the entries that displace the
// current worst: for a table far larger than n that is a few hundred copies.
//
// n <= 0 returns no rows (the scan still runs, so Stats.Entries counts eligible
// and ineligible entries alike).
func TopN(m *ebpf.Map, n int, score func(key, val []byte) (uint64, bool)) ([]Row, Stats, error) {
	var h []Row // min-heap: h[0] is the worst row kept
	worse := func(i, j int) bool { return better(&h[j], &h[i]) }
	siftDown := func(i int) {
		for {
			l, r, w := 2*i+1, 2*i+2, i
			if l < len(h) && worse(l, w) {
				w = l
			}
			if r < len(h) && worse(r, w) {
				w = r
			}
			if w == i {
				return
			}
			h[i], h[w] = h[w], h[i]
			i = w
		}
	}
	siftUp := func(i int) {
		for i > 0 {
			p := (i - 1) / 2
			if !worse(i, p) {
				return
			}
			h[i], h[p] = h[p], h[i]
			i = p
		}
	}

	st, err := Scan(m, func(key, val []byte) bool {
		if n <= 0 {
			return true
		}
		s, ok := score(key, val)
		if !ok {
			return true
		}
		if len(h) == n {
			// Full: only a strictly better entry displaces the worst. Compare
			// against the raw bytes first so a losing entry costs no allocation.
			w := &h[0]
			if s < w.Score || (s == w.Score && bytes.Compare(key, w.Key) >= 0) {
				return true
			}
			w.Key = append(w.Key[:0], key...)
			w.Val = append(w.Val[:0], val...)
			w.Score = s
			siftDown(0)
			return true
		}
		buf := make([]byte, len(key)+len(val))
		copy(buf, key)
		copy(buf[len(key):], val)
		h = append(h, Row{Key: buf[:len(key):len(key)], Val: buf[len(key):], Score: s})
		siftUp(len(h) - 1)
		return true
	})
	if err != nil {
		return nil, st, err
	}
	sort.Slice(h, func(i, j int) bool { return better(&h[i], &h[j]) })
	return h, st, nil
}
