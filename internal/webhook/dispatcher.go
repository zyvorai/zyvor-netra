// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package webhook

import (
	"context"
	"sync"
	"time"
)

// Dispatcher fans events out to all registered sinks.
type Dispatcher struct {
	mu    sync.RWMutex
	sinks []*Sink

	queue chan Event
	quit  chan struct{}
	wg    sync.WaitGroup
}

// NewDispatcher returns a dispatcher with the given queue capacity. A
// non-positive queueSize defaults to 1024.
func NewDispatcher(queueSize int) *Dispatcher {
	if queueSize <= 0 {
		queueSize = 1024
	}
	return &Dispatcher{
		queue: make(chan Event, queueSize),
		quit:  make(chan struct{}),
	}
}

// Add registers a sink. Safe to call before or during Start.
func (d *Dispatcher) Add(s *Sink) {
	d.mu.Lock()
	d.sinks = append(d.sinks, s)
	d.mu.Unlock()
}

// Start launches worker goroutines. A non-positive workers defaults to 1.
func (d *Dispatcher) Start(workers int) {
	if workers <= 0 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
}

// Stop signals workers to exit and waits for them.
func (d *Dispatcher) Stop() {
	close(d.quit)
	d.wg.Wait()
}

// Publish enqueues an event and reports whether it was accepted. If the
// queue is full the event is dropped and false is returned; Publish never
// blocks. A zero Timestamp is filled with time.Now().
func (d *Dispatcher) Publish(ev Event) bool {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	select {
	case d.queue <- ev:
		return true
	default:
		// Intentionally dropped to protect the caller (typically a poll
		// loop) from back-pressure. Callers that need to distinguish
		// accepted-vs-dropped (e.g. edge-triggered events that cannot
		// safely be recomputed next tick) must check the return value.
		return false
	}
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.quit:
			return
		case ev := <-d.queue:
			d.mu.RLock()
			sinks := append([]*Sink(nil), d.sinks...)
			d.mu.RUnlock()
			d.deliver(ev, sinks)
		}
	}
}

// deliver fans an event out to every sink concurrently, so one unreachable
// sink retrying with backoff cannot delay delivery to the other configured
// sinks for the same event. Sinks are still retried sequentially against
// themselves. This worker blocks until all sinks for this event finish (or
// give up) before dequeuing the next event; Start(workers) is how the
// dispatcher gets cross-event concurrency.
func (d *Dispatcher) deliver(ev Event, sinks []*Sink) {
	var wg sync.WaitGroup
	for _, s := range sinks {
		wg.Add(1)
		go func(s *Sink) {
			defer wg.Done()
			d.deliverToSink(s, ev)
		}(s)
	}
	wg.Wait()
}

func (d *Dispatcher) deliverToSink(s *Sink, ev Event) {
	backoff := 200 * time.Millisecond
	maxAttempts := s.cfg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// A bounded window independent of (but slightly longer than) the
		// client's own request timeout, giving slack for connection setup.
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout+2*time.Second)
		err := s.Send(ctx, ev)
		cancel()
		if err == nil {
			return
		}
		if attempt == maxAttempts {
			return
		}
		select {
		case <-d.quit:
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}
