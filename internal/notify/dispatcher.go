// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"context"
	"sync"
	"time"
)

// Dispatcher fans events out to all registered channels.
type Dispatcher struct {
	mu       sync.RWMutex
	channels []Channel

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

// Add registers a channel. Safe to call before or during Start.
func (d *Dispatcher) Add(c Channel) {
	d.mu.Lock()
	d.channels = append(d.channels, c)
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
			chs := append([]Channel(nil), d.channels...)
			d.mu.RUnlock()
			d.deliver(ev, chs)
		}
	}
}

func (d *Dispatcher) deliver(ev Event, chs []Channel) {
	var wg sync.WaitGroup
	for _, c := range chs {
		wg.Add(1)
		go func(c Channel) {
			defer wg.Done()
			d.deliverTo(c, ev)
		}(c)
	}
	wg.Wait()
}

func (d *Dispatcher) deliverTo(c Channel, ev Event) {
	backoff := 200 * time.Millisecond
	maxAttempts := c.MaxAttempts()
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	timeout := c.Timeout()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
		err := c.Send(ctx, ev)
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
