// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	healthSampleMinInterval = 20 * time.Second
	healthSampleMaxAge      = 2 * time.Hour
	healthSampleMaxEntries  = 300
)

// RecordHealthSample appends smp (with At overwritten to now) unless another
// sample was recorded within healthSampleMinInterval, since several
// producers (ebpfHealth, aiBrief/aiDigest, alert.Poller's tick, each polled
// independently and at different cadences) can all call this for the same
// moment in time. Deliberately not part of diskState in persistence.go — see
// the package doc on models.ClusterHealthSample.
func (s *Store) RecordHealthSample(smp models.ClusterHealthSample, now time.Time) {
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.healthSamples); n > 0 && now.Sub(s.healthSamples[n-1].At) < healthSampleMinInterval {
		return
	}
	smp.At = now
	items := append(s.healthSamples, smp)
	cutoff := now.Add(-healthSampleMaxAge)
	first := 0
	for first < len(items) && items[first].At.Before(cutoff) {
		first++
	}
	if first > 0 {
		items = append([]models.ClusterHealthSample(nil), items[first:]...)
	}
	if len(items) > healthSampleMaxEntries {
		items = append([]models.ClusterHealthSample(nil), items[len(items)-healthSampleMaxEntries:]...)
	}
	s.healthSamples = items
}

// HealthHistory returns recorded samples with At >= since (a zero since
// returns everything still retained). Density depends entirely on how often
// something has been polling the controller — see docs/health-trend.md.
func (s *Store) HealthHistory(since time.Time) []models.ClusterHealthSample {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.ClusterHealthSample, 0, len(s.healthSamples))
	for _, smp := range s.healthSamples {
		if !since.IsZero() && smp.At.Before(since) {
			continue
		}
		out = append(out, smp)
	}
	return out
}
