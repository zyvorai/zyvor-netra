// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcherDropsWhenFullWithoutBlocking(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()

	s, _ := New(Config{Name: "t", URL: srv.URL, MaxAttempts: 1})
	d := NewDispatcher(2)
	d.Add(s)
	d.Start(1)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			d.Publish(Event{Kind: "k", Severity: "info"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked")
	}
	close(block)
	d.Stop()
}

func TestPublishReturnsFalseWhenQueueFull(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()

	s, _ := New(Config{Name: "t", URL: srv.URL, MaxAttempts: 1})
	d := NewDispatcher(1)
	d.Add(s)
	d.Start(1)
	defer d.Stop()

	// First publish is picked up by the single worker and blocks on the
	// slow sink; keep publishing until the queue itself (capacity 1) is
	// also full and Publish starts returning false.
	deadline := time.Now().Add(2 * time.Second)
	sawFalse := false
	for time.Now().Before(deadline) {
		if !d.Publish(Event{Severity: "info"}) {
			sawFalse = true
			break
		}
	}
	// Unblock the in-flight handler before the deferred d.Stop()/srv.Close()
	// run, or both deadlock waiting on the still-blocked worker request.
	close(block)
	if !sawFalse {
		t.Fatal("expected Publish to return false once the queue filled up")
	}
}

func TestDispatcherDelivers(t *testing.T) {
	var mu sync.Mutex
	var received []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err == nil {
			mu.Lock()
			received = append(received, ev)
			mu.Unlock()
		}
	}))
	defer srv.Close()

	s, _ := New(Config{Name: "t", URL: srv.URL})
	d := NewDispatcher(64)
	d.Add(s)
	d.Start(2)

	if !d.Publish(Event{Kind: "k", Severity: "warning", Message: "hello"}) {
		t.Fatal("expected Publish to accept the event")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n == 1 {
			d.Stop()
			if received[0].Message != "hello" {
				t.Fatalf("got message %q", received[0].Message)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	d.Stop()
	t.Fatal("event not delivered in time")
}

func TestDispatcherRetriesOnFailure(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 2 {
			http.Error(w, "flaky", http.StatusServiceUnavailable)
			return
		}
	}))
	defer srv.Close()

	s, _ := New(Config{Name: "t", URL: srv.URL, MaxAttempts: 3})
	d := NewDispatcher(4)
	d.Add(s)
	d.Start(1)
	d.Publish(Event{Kind: "k", Severity: "info"})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&attempts) >= 2 {
			d.Stop()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.Stop()
	t.Fatalf("expected at least 2 attempts, got %d", atomic.LoadInt32(&attempts))
}

// TestDispatcherFansOutPerSink verifies that a dead sink retrying with
// backoff does not delay delivery to another sink configured for the same
// event.
func TestDispatcherFansOutPerSink(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer dead.Close()

	var fastHit int32
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fastHit, 1)
	}))
	defer fast.Close()

	deadSink, _ := New(Config{Name: "dead", URL: dead.URL, MaxAttempts: 5, Timeout: 200 * time.Millisecond})
	fastSink, _ := New(Config{Name: "fast", URL: fast.URL, MaxAttempts: 1})

	d := NewDispatcher(4)
	d.Add(deadSink)
	d.Add(fastSink)
	d.Start(1)
	d.Publish(Event{Kind: "k", Severity: "info"})

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&fastHit) >= 1 {
			d.Stop()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.Stop()
	t.Fatal("fast sink was not delivered to promptly despite a slow/dead sink on the same event")
}
