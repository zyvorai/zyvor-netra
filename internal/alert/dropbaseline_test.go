// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"testing"
	"time"
)

func TestDropBaselineTracker_FirstSampleNeverSpikes(t *testing.T) {
	tr := newDropBaselineTracker()
	now := time.Now()
	if _, isSpike := tr.spike("k", now, 500, 6, 3.0, 50); isSpike {
		t.Fatal("first sample should never be a spike")
	}
}

func TestDropBaselineTracker_SteadyGrowthNoSpike(t *testing.T) {
	tr := newDropBaselineTracker()
	now := time.Now()
	count := uint64(0)
	for i := 0; i < 5; i++ {
		count += 100
		now = now.Add(30 * time.Second)
		_, isSpike := tr.spike("k", now, count, 6, 3.0, 50)
		if isSpike {
			t.Fatalf("iteration %d: steady +100/tick growth should not spike", i)
		}
	}
}

func TestDropBaselineTracker_SuddenJumpSpikes(t *testing.T) {
	tr := newDropBaselineTracker()
	now := time.Now()
	count := uint64(0)
	// Establish a quiet baseline: ~10/tick.
	for i := 0; i < 4; i++ {
		count += 10
		now = now.Add(30 * time.Second)
		tr.spike("k", now, count, 6, 3.0, 50)
	}
	// Now a large jump, well above both the multiplier and the absolute floor.
	count += 1000
	now = now.Add(30 * time.Second)
	delta, isSpike := tr.spike("k", now, count, 6, 3.0, 50)
	if !isSpike {
		t.Fatalf("expected a spike, delta=%d", delta)
	}
	if delta != 1000 {
		t.Fatalf("expected delta=1000, got %d", delta)
	}
}

func TestDropBaselineTracker_BelowMinAbsoluteNeverSpikes(t *testing.T) {
	tr := newDropBaselineTracker()
	now := time.Now()
	tr.spike("k", now, 0, 6, 3.0, 50)
	now = now.Add(30 * time.Second)
	// Delta of 10 is a large multiple of a near-zero baseline, but below the
	// absolute floor, so must never fire an alert on noise.
	_, isSpike := tr.spike("k", now, 10, 6, 3.0, 50)
	if isSpike {
		t.Fatal("delta below minAbsolute must never be a spike")
	}
}

func TestDropBaselineTracker_KeysAreIndependent(t *testing.T) {
	tr := newDropBaselineTracker()
	now := time.Now()
	tr.spike("a", now, 1000, 6, 3.0, 50)
	_, isSpike := tr.spike("b", now, 1000, 6, 3.0, 50)
	if isSpike {
		t.Fatal("a new key's first sample should never spike regardless of other keys")
	}
}

func TestDropBaselineTracker_Sweep(t *testing.T) {
	tr := newDropBaselineTracker()
	now := time.Now()
	tr.spike("stale", now, 100, 6, 3.0, 50)
	tr.sweep(now.Add(2*time.Hour), time.Hour)
	if _, ok := tr.history["stale"]; ok {
		t.Fatal("expected stale key to be evicted")
	}
}
