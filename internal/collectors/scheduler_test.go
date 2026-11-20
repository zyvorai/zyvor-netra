// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

type fakeCollector struct {
	name  string
	delay time.Duration
	err   error
}

func (f *fakeCollector) Info() Info { return Info{Name: f.name, Family: "test"} }
func (f *fakeCollector) Collect(_ time.Time, e *Emitter) error {
	time.Sleep(f.delay)
	if f.err != nil {
		return f.err
	}
	e.Gauge(Chart{Context: "test." + f.name}, "v", 1)
	return nil
}

type sink struct {
	mu  sync.Mutex
	got []tsdb.Sample
}

func (s *sink) add(in []tsdb.Sample) {
	s.mu.Lock()
	s.got = append(s.got, in...)
	s.mu.Unlock()
}

func (s *sink) contexts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, x := range s.got {
		out[x.Context]++
	}
	return out
}

func TestSchedulerSkipsSlowCollectorWithoutBlocking(t *testing.T) {
	var sk sink
	s := NewScheduler(nil, sk.add, &fakeCollector{name: "slow", delay: 1500 * time.Millisecond}, &fakeCollector{name: "fast"})
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		s.tick(ctx, now.Add(time.Duration(i)*time.Second))
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	time.Sleep(1600 * time.Millisecond)
	var slow, fast Status
	for _, st := range s.Statuses() {
		switch st.Info.Name {
		case "slow":
			slow = st
		case "fast":
			fast = st
		}
	}
	if slow.Skipped < 2 {
		t.Fatalf("slow collector skipped %d times, want >= 2", slow.Skipped)
	}
	if fast.Runs != 3 || fast.Skipped != 0 {
		t.Fatalf("fast collector blocked: %+v", fast)
	}
	if sk.contexts()["netra.collector_duration"] == 0 {
		t.Fatal("scheduler self metrics missing")
	}
}

func TestSchedulerDisablesPersistentlyFailingCollector(t *testing.T) {
	s := NewScheduler(nil, func([]tsdb.Sample) {}, &fakeCollector{name: "missing", err: errors.New("no such file")})
	for i := 0; i < 30; i++ {
		s.RunOnce(time.Unix(int64(i), 0))
	}
	st := s.Statuses()[0]
	if !st.Disabled || st.Errors != 30 || st.LastError == "" {
		t.Fatalf("status %+v", st)
	}
}
