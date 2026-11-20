package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestRateWindowUsesCounterDeltas(t *testing.T) {
	s := New()
	t0 := time.Now().UTC().Add(-time.Minute)
	s.Report(models.AgentReport{Node: "n1", ObservedAt: t0, Stats: []models.DestinationStat{{Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Packets: 100, Bytes: 1000}}})
	s.Report(models.AgentReport{Node: "n1", ObservedAt: t0.Add(10 * time.Second), Stats: []models.DestinationStat{{Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Packets: 200, Bytes: 3000}}})
	w := s.RateWindow(time.Minute, time.Now())
	if w.Warming || len(w.Metrics) != 1 {
		t.Fatalf("window=%#v", w)
	}
	if got := w.Metrics[0].PacketsPerSecond; got != 10 {
		t.Fatalf("pps=%v", got)
	}
	if got := w.Metrics[0].BytesPerSecond; got != 200 {
		t.Fatalf("bps=%v", got)
	}
}

func TestRateCounterResetSkipsInterval(t *testing.T) {
	s := New()
	t0 := time.Now().UTC().Add(-time.Minute)
	s.Report(models.AgentReport{Node: "n1", ObservedAt: t0, Stats: []models.DestinationStat{{Packets: 1000}}})
	s.Report(models.AgentReport{Node: "n1", ObservedAt: t0.Add(10 * time.Second), Stats: []models.DestinationStat{{Packets: 2}}})
	w := s.RateWindow(time.Minute, time.Now())
	if len(w.Metrics) != 0 {
		t.Fatalf("counter reset should not create a rate: %#v", w.Metrics)
	}
}

func TestRateBaselinePersistsButWindowWarmsAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Add(-time.Minute)
	s.Report(models.AgentReport{Node: "n1", ObservedAt: t0, ConnectionAttempts: []models.ConnectionAttemptStat{{Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Attempts: 10}}})
	s.Report(models.AgentReport{Node: "n1", ObservedAt: t0.Add(10 * time.Second), ConnectionAttempts: []models.ConnectionAttemptStat{{Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Attempts: 30}}})
	b, err := s.CaptureRateBaseline(time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Entries) == 0 {
		t.Fatal("expected rate baseline entries")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if len(s2.RateBaseline().Entries) == 0 {
		t.Fatal("persisted rate baseline missing")
	}
	if !s2.RateWindow(time.Minute, time.Now()).Warming {
		t.Fatal("rate history must warm after restart")
	}
}
