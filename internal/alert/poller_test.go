// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/notify"
	"github.com/zyvorai/netra/internal/webhook"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newTestPoller(cfg Config, published *[]notify.Event) *Poller {
	cfg.applyDefaults()
	var mu sync.Mutex
	return &Poller{
		log: discardLogger(),
		fetch: func(now time.Time, staleAfter time.Duration) []models.AgentStatus {
			return nil
		},
		publish: func(ev notify.Event) bool {
			mu.Lock()
			*published = append(*published, ev)
			mu.Unlock()
			return true
		},
		now:   time.Now,
		cfg:   cfg,
		dedup: newDedupState(),
	}
}

func TestDedupSuppressesRepeatWithinCooldown(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute}, dedup: newDedupState()}
	ev := notify.Event{Source: "health", Kind: "x", Subject: "s", Severity: "warning"}
	base := time.Unix(1000, 0)

	if !p.dedup.shouldFire(base, p.cfg.Cooldown, ev) {
		t.Fatal("first occurrence should fire")
	}
	if p.dedup.shouldFire(base.Add(10*time.Second), p.cfg.Cooldown, ev) {
		t.Fatal("repeat within cooldown should be suppressed")
	}
	if !p.dedup.shouldFire(base.Add(2*time.Minute), p.cfg.Cooldown, ev) {
		t.Fatal("repeat after cooldown elapsed should fire")
	}
}

func TestDedupAlwaysFiresOnEscalation(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Hour}, dedup: newDedupState()}
	base := time.Unix(1000, 0)
	warn := notify.Event{Source: "health", Kind: "x", Subject: "s", Severity: "warning"}
	crit := notify.Event{Source: "health", Kind: "x", Subject: "s", Severity: "critical"}

	if !p.dedup.shouldFire(base, p.cfg.Cooldown, warn) {
		t.Fatal("first occurrence should fire")
	}
	if !p.dedup.shouldFire(base.Add(time.Second), p.cfg.Cooldown, crit) {
		t.Fatal("severity escalation should fire immediately, ignoring cooldown")
	}
	// De-escalating back to warning, still inside cooldown, should be suppressed.
	if p.dedup.shouldFire(base.Add(2*time.Second), p.cfg.Cooldown, warn) {
		t.Fatal("de-escalation within cooldown should be suppressed")
	}
}

func TestDedupSweepEvictsOldEntries(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute}, dedup: newDedupState()}
	base := time.Unix(1000, 0)
	ev := notify.Event{Source: "health", Kind: "x", Subject: "s", Severity: "info"}
	p.dedup.shouldFire(base, p.cfg.Cooldown, ev)

	p.dedup.sweep(base.Add(30*time.Minute), p.cfg.Cooldown) // within max(cooldown*8, 1h) => not evicted
	if len(p.dedup.last) != 1 {
		t.Fatalf("expected entry to survive an early sweep, got %d entries", len(p.dedup.last))
	}

	p.dedup.sweep(base.Add(2*time.Hour), p.cfg.Cooldown) // past max age => evicted
	if len(p.dedup.last) != 0 {
		t.Fatalf("expected entry to be evicted, got %d entries", len(p.dedup.last))
	}
}

func TestEvaluateSkipsDeadAgentsImplicitlyViaSources(t *testing.T) {
	// health/pathdiag/dropdiag.Build already skip stale agents internally;
	// this is a smoke test that evaluate() runs the full pipeline without
	// panicking against a minimal fixture and respects dedup across two
	// calls with the same data.
	var published []notify.Event
	p := newTestPoller(Config{}, &published)
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1"}}}

	now := time.Unix(2000, 0)
	first, _ := p.evaluate(now, agents)
	second, _ := p.evaluate(now.Add(time.Second), agents)
	if len(first) != 0 && len(second) != 0 {
		// Both should be empty for an agent with no data triggering any
		// threshold, but if any anomaly logic ever changes to fire on an
		// empty agent, dedup must still suppress the immediate repeat.
		t.Fatalf("expected repeat evaluate() within cooldown to be deduped, got %d then %d events", len(first), len(second))
	}
}

func TestEvaluateEmitsAIDigestOnCriticalHealth(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute}, dedup: newDedupState()}
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			Mode: "observe",
			TCPHealth: []models.TCPHealthStat{{
				Namespace: "pay",
				Pod:       "api",
				SRTTUS:    800_000,
			}},
		},
	}}
	now := time.Unix(3000, 0)
	evs, sample := p.evaluate(now, agents)
	if sample.Severity == "" {
		t.Fatalf("expected a populated cluster-health sample alongside events, got %#v", sample)
	}
	var digest *notify.Event
	for i := range evs {
		if evs[i].Source == "ai" && evs[i].Kind == "digest" {
			digest = &evs[i]
		}
	}
	if digest == nil {
		t.Fatalf("expected an ai/digest event among %d events", len(evs))
	}
	if digest.Fingerprint == "" || digest.Card == "" || digest.Text == "" {
		t.Fatalf("digest missing fingerprint/card/text: %+v", digest)
	}
	again, _ := p.evaluate(now.Add(time.Second), agents)
	for _, ev := range again {
		if ev.Source == "ai" && ev.Kind == "digest" {
			t.Fatal("digest should be deduped within cooldown while fingerprint is unchanged")
		}
	}
}

func TestEvaluateAIDigestCardExplainsFingerprintChange(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute}, dedup: newDedupState()}
	quiet := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1"}}}
	degraded := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			Mode: "observe",
			TCPHealth: []models.TCPHealthStat{{
				Namespace: "pay",
				Pod:       "api",
				SRTTUS:    800_000,
			}},
		},
	}}
	now := time.Unix(4000, 0)
	// First call seeds internal/ai's shared "last fingerprint" state to a
	// known baseline, regardless of whatever this test binary's earlier
	// tests already left it at — digestEvent() always calls
	// ai.BuildDigest() (which records the fingerprint) even when it
	// decides not to return an event for a quiet cluster.
	p.evaluate(now, quiet)

	evs, _ := p.evaluate(now.Add(time.Second), degraded)
	var digest *notify.Event
	for i := range evs {
		if evs[i].Source == "ai" && evs[i].Kind == "digest" {
			digest = &evs[i]
		}
	}
	if digest == nil {
		t.Fatalf("expected an ai/digest event among %d events", len(evs))
	}
	if !strings.Contains(digest.Card, "Why:") {
		t.Fatalf("card missing a Why: section for a changed fingerprint: %s", digest.Card)
	}
}

func TestNewSinceStartEventsNilWithoutFetchPods(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute}, dedup: newDedupState()}
	if got := p.newSinceStartEvents(time.Now(), nil); got != nil {
		t.Fatalf("expected nil with fetchPods unset, got %#v", got)
	}
}

func TestNewSinceStartEventsNilWithoutCapturedBaseline(t *testing.T) {
	p := &Poller{
		cfg:      Config{Cooldown: time.Minute},
		dedup:    newDedupState(),
		baseline: func() models.BehaviorBaseline { return models.BehaviorBaseline{} },
		fetchPods: func(ctx context.Context, ns string) ([]models.PodInfo, error) {
			t.Fatal("must not fetch pods without a captured baseline")
			return nil, nil
		},
	}
	if got := p.newSinceStartEvents(time.Now(), nil); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
}

func TestNewSinceStartEventsFiresForPodStartedAfterBaseline(t *testing.T) {
	baselineAt := time.Now().Add(-time.Hour)
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{TLSMetadata: []models.TLSMetadataStat{
		{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "new.example.com", Handshakes: 3},
	}}}}
	started := baselineAt.Add(time.Minute)
	p := &Poller{
		log:      discardLogger(),
		cfg:      Config{Cooldown: time.Minute, MaxPodRestarts: 5},
		dedup:    newDedupState(),
		restarts: newRestartTracker(),
		baseline: func() models.BehaviorBaseline {
			return models.BehaviorBaseline{SchemaVersion: 1, CapturedAt: baselineAt}
		},
		fetchPods: func(ctx context.Context, ns string) ([]models.PodInfo, error) {
			return []models.PodInfo{{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: &started}}, nil
		},
	}
	evs := p.newSinceStartEvents(time.Now(), agents)
	if len(evs) != 1 || evs[0].Source != "new-since-start" {
		t.Fatalf("events=%#v", evs)
	}
}

func TestNewSinceStartEventsSuppressedOnRestartBetweenPolls(t *testing.T) {
	baselineAt := time.Now().Add(-time.Hour)
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{TLSMetadata: []models.TLSMetadataStat{
		{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "new.example.com", Handshakes: 3},
	}}}}
	started := baselineAt.Add(time.Minute)
	restartCount := 1
	p := &Poller{
		log:      discardLogger(),
		cfg:      Config{Cooldown: time.Millisecond, MaxPodRestarts: 5},
		dedup:    newDedupState(),
		restarts: newRestartTracker(),
		baseline: func() models.BehaviorBaseline {
			return models.BehaviorBaseline{SchemaVersion: 1, CapturedAt: baselineAt}
		},
		fetchPods: func(ctx context.Context, ns string) ([]models.PodInfo, error) {
			return []models.PodInfo{{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: &started, RestartCount: restartCount}}, nil
		},
	}
	// First tick establishes the restart-count baseline in the tracker.
	first := p.newSinceStartEvents(time.Now(), agents)
	if len(first) != 1 {
		t.Fatalf("first tick events=%#v, want 1", first)
	}
	// Restart count increases between polls — this cycle must suppress.
	restartCount = 2
	time.Sleep(2 * time.Millisecond)
	second := p.newSinceStartEvents(time.Now(), agents)
	if len(second) != 0 {
		t.Fatalf("expected suppression on a restart-count increase, got %#v", second)
	}
}

func TestTickRecordsHealthSampleEvenWhenQuiet(t *testing.T) {
	var recorded []models.ClusterHealthSample
	p := &Poller{
		log:     discardLogger(),
		fetch:   func(now time.Time, staleAfter time.Duration) []models.AgentStatus { return nil },
		publish: func(notify.Event) bool { return true },
		record: func(s models.ClusterHealthSample, now time.Time) {
			recorded = append(recorded, s)
		},
		now:   time.Now,
		cfg:   Config{Cooldown: time.Minute},
		dedup: newDedupState(),
	}
	p.tick()
	if len(recorded) != 1 {
		t.Fatalf("recorded=%d, want 1 (a sample must be recorded even for a quiet tick with no events)", len(recorded))
	}
	if recorded[0].Severity == "" {
		t.Fatalf("recorded sample missing severity: %#v", recorded[0])
	}
}

func TestTickToleratesNilRecord(t *testing.T) {
	p := newTestPoller(Config{}, &[]notify.Event{})
	p.record = nil
	p.tick() // must not panic
}

// TestEndToEndDispatch wires a real Poller to a real notify.Dispatcher and
// an httptest fake webhook channel, confirming an event survives the full
// path with the expected JSON body.
func TestEndToEndDispatch(t *testing.T) {
	var hits int32
	var mu sync.Mutex
	var gotSource string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev notify.Event
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		gotSource = ev.Source
		mu.Unlock()
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	ch, err := notify.NewWebhookChannel(webhook.Config{Name: "t", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	d := notify.NewDispatcher(16)
	d.Add(ch)
	d.Start(1)
	defer d.Stop()

	p := &Poller{
		log:     discardLogger(),
		publish: d.Publish,
		now:     time.Now,
		cfg:     Config{Cooldown: time.Minute},
		dedup:   newDedupState(),
	}
	ev := notify.Event{Source: "health", Kind: "k", Subject: "s", Severity: "warning", Message: "m"}
	if !p.dedup.shouldFire(time.Now(), p.cfg.Cooldown, ev) {
		t.Fatal("expected first occurrence to fire")
	}
	if !p.publish(ev) {
		t.Fatal("expected publish to accept the event")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&hits) >= 1 {
			mu.Lock()
			got := gotSource
			mu.Unlock()
			if got != "health" {
				t.Fatalf("got source %q, want health", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("event was not delivered end-to-end in time")
}
