// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestRecordHealthSampleThrottlesWithinMinInterval(t *testing.T) {
	s := New()
	t0 := time.Now().UTC()
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 90}, t0)
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 10}, t0.Add(5*time.Second))
	hist := s.HealthHistory(time.Time{})
	if len(hist) != 1 {
		t.Fatalf("history=%d, want 1 (second sample within min interval should be dropped)", len(hist))
	}
	if hist[0].HealthScore != 90 {
		t.Fatalf("healthScore=%d, want 90 (throttled sample must not overwrite the kept one)", hist[0].HealthScore)
	}
}

func TestRecordHealthSampleAcceptsAfterMinInterval(t *testing.T) {
	s := New()
	t0 := time.Now().UTC()
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 90}, t0)
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 80}, t0.Add(healthSampleMinInterval+time.Second))
	hist := s.HealthHistory(time.Time{})
	if len(hist) != 2 {
		t.Fatalf("history=%d, want 2", len(hist))
	}
}

func TestHealthHistoryFiltersBySince(t *testing.T) {
	s := New()
	t0 := time.Now().UTC()
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 1}, t0)
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 2}, t0.Add(healthSampleMinInterval+time.Second))
	hist := s.HealthHistory(t0.Add(healthSampleMinInterval))
	if len(hist) != 1 || hist[0].HealthScore != 2 {
		t.Fatalf("hist=%#v", hist)
	}
}

func TestHealthHistoryTrimsToMaxAge(t *testing.T) {
	s := New()
	t0 := time.Now().UTC()
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 1}, t0)
	s.RecordHealthSample(models.ClusterHealthSample{HealthScore: 2}, t0.Add(healthSampleMaxAge+time.Minute))
	hist := s.HealthHistory(time.Time{})
	if len(hist) != 1 || hist[0].HealthScore != 2 {
		t.Fatalf("hist=%#v, want only the sample within max age", hist)
	}
}

func TestHealthHistoryCapsEntryCount(t *testing.T) {
	s := New()
	t0 := time.Now().UTC()
	for i := 0; i < healthSampleMaxEntries+10; i++ {
		s.RecordHealthSample(models.ClusterHealthSample{HealthScore: i}, t0.Add(time.Duration(i)*healthSampleMinInterval))
	}
	hist := s.HealthHistory(time.Time{})
	if len(hist) != healthSampleMaxEntries {
		t.Fatalf("history=%d, want cap %d", len(hist), healthSampleMaxEntries)
	}
	if hist[0].HealthScore != 10 {
		t.Fatalf("oldest retained sample HealthScore=%d, want 10 (the first 10 should have been trimmed)", hist[0].HealthScore)
	}
}
