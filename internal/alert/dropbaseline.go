// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"sync"
	"time"
)

// dropBaselineTracker keeps a short rolling history of per-key cumulative
// drop counts across ticks — the cross-tick memory dropdiag.Build's
// point-in-time anomalies don't carry (its anomalies() only ever looks at
// one snapshot, so it can flag "drops are nonzero" but not "drops just
// spiked"). Same in-memory-only, no-persistence discipline as
// restartTracker/dedupState: state resets on restart, an accepted cost
// consistent with the rest of this package.
type dropBaselineTracker struct {
	mu      sync.Mutex
	history map[string][]dropSample
}

type dropSample struct {
	at    time.Time
	count uint64
}

func newDropBaselineTracker() *dropBaselineTracker {
	return &dropBaselineTracker{history: map[string][]dropSample{}}
}

// spike records count for key at now and reports whether the delta since
// the previous sample is a meaningful jump above key's own recent baseline:
// the average per-interval delta over the trailing window (excluding the
// newest sample), scaled by multiplier, with a minAbsolute floor so a
// near-zero baseline doesn't make a handful of drops register as an
// infinite-multiple spike. The first sample for a key is never a spike —
// there is no baseline yet.
func (t *dropBaselineTracker) spike(key string, now time.Time, count uint64, window int, multiplier float64, minAbsolute uint64) (delta uint64, isSpike bool) {
	if window < 2 {
		window = 2
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	hist := t.history[key]
	if len(hist) == 0 {
		t.history[key] = append(hist, dropSample{now, count})
		return 0, false
	}
	prev := hist[len(hist)-1]
	if count > prev.count {
		delta = count - prev.count
	}

	// Deltas between consecutive samples, oldest-first, excluding the delta
	// we just computed (that's the candidate, not part of its own baseline).
	var deltas []uint64
	for i := 1; i < len(hist); i++ {
		if hist[i].count > hist[i-1].count {
			deltas = append(deltas, hist[i].count-hist[i-1].count)
		} else {
			deltas = append(deltas, 0)
		}
	}

	hist = append(hist, dropSample{now, count})
	if len(hist) > window {
		hist = hist[len(hist)-window:]
	}
	t.history[key] = hist

	if len(deltas) == 0 {
		return delta, false
	}
	var sum uint64
	for _, d := range deltas {
		sum += d
	}
	avg := float64(sum) / float64(len(deltas))
	isSpike = delta > minAbsolute && float64(delta) > multiplier*avg
	return delta, isSpike
}

// sweep evicts keys whose newest sample is older than maxAge, mirroring
// dedupState.sweep's eviction discipline so a long-running controller
// doesn't accumulate unbounded history for reason keys that stopped
// appearing (e.g. a node removed from the cluster).
func (t *dropBaselineTracker) sweep(now time.Time, maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, hist := range t.history {
		if len(hist) == 0 || now.Sub(hist[len(hist)-1].at) > maxAge {
			delete(t.history, k)
		}
	}
}
