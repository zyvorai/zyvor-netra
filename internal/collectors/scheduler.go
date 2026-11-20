// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// Status reports the health of one collector.
type Status struct {
	Info       Info      `json:"info"`
	Runs       uint64    `json:"runs"`
	Errors     uint64    `json:"errors"`
	Skipped    uint64    `json:"skipped"`
	LastError  string    `json:"lastError,omitempty"`
	LastRun    time.Time `json:"lastRun"`
	LastMillis float64   `json:"lastMillis"`
	Samples    int       `json:"samples"`
	Disabled   bool      `json:"disabled,omitempty"`
}

type entry struct {
	c       Collector
	info    Info
	em      *Emitter
	running atomic.Bool
	mu      sync.Mutex
	st      Status
	// failStreak disables a collector whose source does not exist on this
	// host (for example no /proc/pressure) after repeated errors.
	failStreak int
}

// Scheduler runs collectors on their own cadence. A collector still running
// when its next tick arrives is skipped and counted; it never delays the
// others.
type Scheduler struct {
	log     *slog.Logger
	sink    func([]tsdb.Sample)
	entries []*entry
	self    Chart
	selfEm  *Emitter
}

// NewScheduler creates a scheduler that hands every run's samples to sink.
// sink must be safe for concurrent use.
func NewScheduler(log *slog.Logger, sink func([]tsdb.Sample), cs ...Collector) *Scheduler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Scheduler{log: log, sink: sink, selfEm: NewEmitter()}
	for _, c := range cs {
		s.Add(c)
	}
	return s
}

// Add registers a collector. Call before Run.
func (s *Scheduler) Add(c Collector) {
	info := c.Info()
	if info.Every <= 0 {
		info.Every = time.Second
	}
	s.entries = append(s.entries, &entry{c: c, info: info, em: NewEmitter(), st: Status{Info: info}})
}

// Statuses returns every collector's status sorted by name.
func (s *Scheduler) Statuses() []Status {
	out := make([]Status, 0, len(s.entries))
	for _, e := range s.entries {
		e.mu.Lock()
		out = append(out, e.st)
		e.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info.Name < out[j].Info.Name })
	return out
}

// RunOnce runs every due collector synchronously. Used by tests.
func (s *Scheduler) RunOnce(now time.Time) {
	var wg sync.WaitGroup
	for _, e := range s.entries {
		wg.Add(1)
		go func(e *entry) {
			defer wg.Done()
			s.runEntry(e, now)
		}(e)
	}
	wg.Wait()
	s.emitSelf(now)
}

// Run ticks at one-second boundaries until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	align := time.Until(time.Now().Truncate(time.Second).Add(time.Second))
	select {
	case <-ctx.Done():
		return
	case <-time.After(align):
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	s.tick(ctx, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.tick(ctx, now)
		}
	}
}

func (s *Scheduler) tick(ctx context.Context, now time.Time) {
	sec := now.Truncate(time.Second)
	for _, e := range s.entries {
		every := int64(e.info.Every / time.Second)
		if every > 1 && sec.Unix()%every != 0 {
			continue
		}
		e.mu.Lock()
		disabled := e.st.Disabled
		e.mu.Unlock()
		if disabled {
			continue
		}
		if !e.running.CompareAndSwap(false, true) {
			e.mu.Lock()
			e.st.Skipped++
			e.mu.Unlock()
			continue
		}
		go func(e *entry) {
			defer e.running.Store(false)
			if ctx.Err() == nil {
				s.runEntry(e, sec)
			}
		}(e)
	}
	s.emitSelf(sec)
}

func (s *Scheduler) runEntry(e *entry, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			e.mu.Lock()
			e.st.Errors++
			e.st.LastError = "panic"
			e.mu.Unlock()
			s.log.Error("collector panic", "collector", e.info.Name, "panic", r)
		}
	}()
	start := time.Now()
	e.em.Begin(now)
	err := e.c.Collect(now, e.em)
	e.em.End()
	samples := append([]tsdb.Sample(nil), e.em.Samples()...)
	e.mu.Lock()
	e.st.Runs++
	e.st.LastRun = now
	e.st.LastMillis = float64(time.Since(start).Microseconds()) / 1000
	e.st.Samples = len(samples)
	if err != nil {
		e.st.Errors++
		e.st.LastError = err.Error()
		e.failStreak++
		if e.failStreak >= 30 && len(samples) == 0 {
			e.st.Disabled = true
			s.log.Warn("collector disabled after repeated errors", "collector", e.info.Name, "error", err)
		}
	} else {
		e.failStreak = 0
		e.st.LastError = ""
	}
	e.mu.Unlock()
	if len(samples) > 0 && s.sink != nil {
		s.sink(samples)
	}
}

// emitSelf publishes the scheduler's own health as netra.collector.* metrics.
func (s *Scheduler) emitSelf(now time.Time) {
	if s.sink == nil {
		return
	}
	s.selfEm.Begin(now)
	for _, st := range s.Statuses() {
		lbl := map[string]string{"collector": st.Info.Name}
		dur := Chart{Context: "netra.collector_duration", ID: "netra.collector_duration_" + st.Info.Name, Family: "netra", Units: "ms", Title: "Collector run time", Labels: lbl}
		s.selfEm.Gauge(dur, "duration", st.LastMillis)
		ev := Chart{Context: "netra.collector_events", ID: "netra.collector_events_" + st.Info.Name, Family: "netra", Units: "events/s", Title: "Collector errors and skipped runs", Labels: lbl}
		s.selfEm.Incremental(ev, "errors", float64(st.Errors), 1)
		s.selfEm.Incremental(ev, "skipped", float64(st.Skipped), 1)
		dis := 0.0
		if st.Disabled {
			dis = 1
		}
		s.selfEm.Gauge(Chart{Context: "netra.collector_disabled", ID: "netra.collector_disabled_" + st.Info.Name, Family: "netra", Units: "boolean", Title: "Collector disabled", Labels: lbl}, "disabled", dis)
	}
	s.selfEm.End()
	if out := s.selfEm.Samples(); len(out) > 0 {
		s.sink(append([]tsdb.Sample(nil), out...))
	}
}
