// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/alert"
	"github.com/zyvorai/netra/internal/gitops"
	"github.com/zyvorai/netra/internal/ha"
	"github.com/zyvorai/netra/internal/kube"
)

// leaseDoc mirrors the JSON wire shape internal/kube's unexported
// leaseDocument reads and writes (see internal/kube/lease.go) closely
// enough to fake the coordination.k8s.io/v1 Lease API's GET/POST/PUT
// semantics that TryAcquireOrRenewLease/ReleaseLease depend on:
// optimistic concurrency via resourceVersion, one holderIdentity per
// lease. Duplicated here rather than imported because the real type is
// unexported and this test lives in package main, not package kube.
type leaseDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace,omitempty"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string `json:"holderIdentity,omitempty"`
		LeaseDurationSeconds int32  `json:"leaseDurationSeconds,omitempty"`
		AcquireTime          string `json:"acquireTime,omitempty"`
		RenewTime            string `json:"renewTime,omitempty"`
		LeaseTransitions     int32  `json:"leaseTransitions,omitempty"`
	} `json:"spec"`
}

// fakeLeaseServer is a minimal in-memory coordination.k8s.io/v1 Lease
// API, adapted from internal/kube/lease_test.go's fakeLeaseAPI so two
// concurrent electionLoop "replicas" in this test race for the same
// lease exactly as they would against a real Kubernetes API server.
type fakeLeaseServer struct {
	mu    sync.Mutex
	lease *leaseDoc
	rv    int
}

func (f *fakeLeaseServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !strings.Contains(r.URL.Path, "/leases") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if f.lease == nil {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(f.lease)
	case http.MethodPost:
		if f.lease != nil {
			http.Error(w, `{"reason":"Conflict"}`, http.StatusConflict)
			return
		}
		var x leaseDoc
		if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f.rv++
		x.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.lease = &x
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(x)
	case http.MethodPut:
		if f.lease == nil {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		var x leaseDoc
		if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if x.Metadata.ResourceVersion != f.lease.Metadata.ResourceVersion {
			http.Error(w, `{"reason":"Conflict"}`, http.StatusConflict)
			return
		}
		f.rv++
		x.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.lease = &x
		_ = json.NewEncoder(w).Encode(x)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

// promotionEvent timestamps one "controller promoted"/"controller
// demoted" log line, per replica identity.
type promotionEvent struct {
	at       time.Time
	identity string
	kind     string // "promoted" or "demoted"
}

// promotionRecorder is a slog.Handler that timestamps every promote/
// demote log line electionLoop emits. "controller demoted" is only
// logged in electionLoop's demote() after syslogWG.Wait()/
// snowflakeWG.Wait() return, i.e. after the push-sink goroutine has
// fully stopped — so the [promoted, demoted] window recorded here is a
// safe superset of the sink's true active window. Proving these
// windows never overlap between two identities therefore proves the
// real sink-active windows never overlap either.
type promotionRecorder struct {
	mu     sync.Mutex
	events []promotionEvent
}

func (r *promotionRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *promotionRecorder) Handle(_ context.Context, rec slog.Record) error {
	var kind string
	switch rec.Message {
	case "controller promoted":
		kind = "promoted"
	case "controller demoted":
		kind = "demoted"
	default:
		return nil
	}
	var identity string
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "identity" {
			identity = a.Value.String()
		}
		return true
	})
	r.mu.Lock()
	r.events = append(r.events, promotionEvent{at: time.Now(), identity: identity, kind: kind})
	r.mu.Unlock()
	return nil
}

func (r *promotionRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *promotionRecorder) WithGroup(string) slog.Handler      { return r }

// TestElectionLoopNeverDoubleShipsPushSinks races two electionLoop
// "replicas" against one shared fake lease backend and one shared
// state file (real flock semantics — see internal/store/persistence.go
// — since each replica opens its own *os.File on the same path), forces
// a mid-test handoff, and proves the two replicas' leadership windows
// never overlap. That non-overlap is exactly the invariant startSyslog
// and startSnowflake both rely on to avoid double-shipping the same
// audit stream to a collector or warehouse.
//
// This exercises the syslog forwarder, not Snowflake: a bad/unreachable
// Snowflake account makes startSnowflake call os.Exit(1) by design (see
// its doc comment) — fine in production (fail fast on bad config), fatal
// to a test binary. startSyslog and startSnowflake share the exact same
// call sites, cancel vars, and Wait()-before-"controller demoted"
// teardown order in electionLoop (main.go), so proving the invariant
// holds for one proves the shared wiring both depend on.
func TestElectionLoopNeverDoubleShipsPushSinks(t *testing.T) {
	fakeLease := &fakeLeaseServer{}
	ts := httptest.NewServer(fakeLease)
	defer ts.Close()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()
	t.Setenv("NETRA_SYSLOG_ADDR", udpConn.LocalAddr().String())
	t.Setenv("NETRA_SYSLOG_INTERVAL", "20ms")

	stateFile := filepath.Join(t.TempDir(), "state.json")
	rec := &promotionRecorder{}
	log := slog.New(rec)

	const (
		leaseDuration = 200 * time.Millisecond
		renewDeadline = 140 * time.Millisecond
		retryPeriod   = 30 * time.Millisecond
	)
	run := func(ctx context.Context, wg *sync.WaitGroup, identity string) {
		defer wg.Done()
		k := kube.NewForTesting(ts.URL, ts.Client())
		gate := ha.NewGate(identity, "test")
		electionLoop(ctx, log, k, nil, gate, stateFile, "netra", "controller", identity,
			leaseDuration, renewDeadline, retryPeriod,
			nil, alert.Config{}, nil, gitops.Config{}, false)
	}

	parent, cancelAll := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancelAll()

	var wg sync.WaitGroup
	ctxA, cancelA := context.WithCancel(parent)
	wg.Add(1)
	go run(ctxA, &wg, "replica-a")

	// Let replica-a win the initial race deterministically before
	// replica-b joins, so the test reliably exercises a real handoff
	// (below) rather than depending on luck to ever see one.
	time.Sleep(70 * time.Millisecond)

	ctxB, cancelB := context.WithCancel(parent)
	defer cancelB()
	wg.Add(1)
	go run(ctxB, &wg, "replica-b")

	// Force replica-a to release mid-test; replica-b should pick up the
	// lease shortly after via its own retry ticker.
	time.Sleep(230 * time.Millisecond)
	cancelA()

	wg.Wait()

	rec.mu.Lock()
	events := append([]promotionEvent(nil), rec.events...)
	rec.mu.Unlock()

	if len(events) == 0 {
		t.Fatal("no promote/demote events observed — test setup is broken")
	}
	sawHandoff := false
	for _, e := range events {
		if e.identity == "replica-b" && e.kind == "promoted" {
			sawHandoff = true
		}
	}
	if !sawHandoff {
		t.Fatal("replica-b never took leadership — test did not exercise a handoff")
	}

	type window struct{ start, end time.Time }
	open := map[string]time.Time{}
	var windows []window
	var owners []string
	last := events[len(events)-1].at
	for _, e := range events {
		switch e.kind {
		case "promoted":
			open[e.identity] = e.at
		case "demoted":
			if start, ok := open[e.identity]; ok {
				windows = append(windows, window{start, e.at})
				owners = append(owners, e.identity)
				delete(open, e.identity)
			}
		}
	}
	// Any identity still leader when the test's parent context expired
	// closes its window at the last observed event — a safe upper bound.
	for id, start := range open {
		windows = append(windows, window{start, last})
		owners = append(owners, id)
	}

	for i := range windows {
		for j := i + 1; j < len(windows); j++ {
			if owners[i] == owners[j] {
				continue
			}
			if windows[i].start.Before(windows[j].end) && windows[j].start.Before(windows[i].end) {
				t.Fatalf("leadership windows overlap: %s %v .. %v vs %s %v .. %v — double-ship risk",
					owners[i], windows[i].start, windows[i].end,
					owners[j], windows[j].start, windows[j].end)
			}
		}
	}
	t.Logf("observed %d promote/demote events across %d leadership windows, no overlap", len(events), len(windows))
}
