// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/mapscan"
	"github.com/zyvorai/netra/internal/models"
)

// slowScan is the duration above which one map read is logged: the agent reads
// its big tables every few seconds, so a scan approaching that interval means the
// agent is spending most of a core on it.
const slowScan = time.Second

// recordScan remembers what one map read cost, for the report.
func (a *Agent) recordScan(name string, st mapscan.Stats, took time.Duration) {
	a.scanMu.Lock()
	if a.scans == nil {
		a.scans = map[string]models.MapScanStat{}
	}
	a.scans[name] = models.MapScanStat{
		Map: name, Entries: st.Entries, Syscalls: st.Syscalls, Batched: st.Batched,
		Millis: float64(took) / float64(time.Millisecond),
	}
	a.scanMu.Unlock()
	if took >= slowScan {
		a.log.Warn("slow BPF map read", "map", name, "entries", st.Entries, "syscalls", st.Syscalls, "batched", st.Batched, "took", took.String())
	}
}

// mapScans returns the latest read cost of every map read so far, by name.
func (a *Agent) mapScans() []models.MapScanStat {
	a.scanMu.Lock()
	out := make([]models.MapScanStat, 0, len(a.scans))
	for _, s := range a.scans {
		out = append(out, s)
	}
	a.scanMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Map < out[j].Map })
	return out
}

// topRows returns the n best entries of the named map by score, best first, as
// raw key/value bytes: the caller decodes only these. keySize and valSize are the
// layout the caller decodes, checked against the map so a mismatch fails loudly
// (as reading into a fixed-size array used to) instead of misreading.
func (a *Agent) topRows(name string, n, keySize, valSize int, score func(k, v []byte) (uint64, bool)) ([]mapscan.Row, error) {
	m := a.collection.Maps[name]
	if m == nil {
		return nil, fmt.Errorf("%s unavailable", name)
	}
	if int(m.KeySize()) != keySize || int(m.ValueSize()) != valSize {
		return nil, fmt.Errorf("%s has key/value size %d/%d, the agent reads %d/%d", name, m.KeySize(), m.ValueSize(), keySize, valSize)
	}
	start := time.Now()
	rows, st, err := mapscan.TopN(m, n, score)
	a.recordScan(name, st, time.Since(start))
	if err = mapIterErr(err); err != nil {
		return nil, err
	}
	return rows, nil
}

// countEntries counts the entries of the named map (capped, like before), or 0
// if the map does not exist.
func (a *Agent) countEntries(name string) (int, error) {
	m := a.collection.Maps[name]
	if m == nil {
		return 0, nil
	}
	const limit = 1_000_000
	start := time.Now()
	n := 0
	st, err := mapscan.Scan(m, func(_, _ []byte) bool {
		n++
		return n < limit
	})
	a.recordScan(name, st, time.Since(start))
	return n, mapIterErr(err)
}
