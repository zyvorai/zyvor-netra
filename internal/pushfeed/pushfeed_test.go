// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package pushfeed

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/siem"
)

var t0 = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// audit returns n events newest-first, one second apart from base.
func audit(base time.Time, n int) []models.AuditEvent {
	out := make([]models.AuditEvent, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, models.AuditEvent{At: base.Add(time.Duration(i) * time.Second), Actor: "op", Action: "policy.apply", Target: fmt.Sprintf("p%d", i)})
	}
	return out
}

func blockEv(at time.Time) models.FastPathEvent {
	return models.FastPathEvent{ObservedAt: at, Action: "blocked", DestinationIP: "1.2.3.4", Protocol: "tcp", Reason: "denylist"}
}

// recorder is a Send that records batch sizes and can be told to fail.
type recorder struct {
	sizes []int
	fail  func(call int) error
	first []string // first target of each batch
}

func (r *recorder) send(recs []siem.Record) error {
	call := len(r.sizes)
	r.sizes = append(r.sizes, len(recs))
	r.first = append(r.first, recs[0].Target)
	if r.fail != nil {
		return r.fail(call)
	}
	return nil
}

func TestAuditIsSentOnceThenSuppressedByTheWatermark(t *testing.T) {
	f := New("test", quiet())
	var r recorder
	f.DrainAudit(audit(t0, 3), 500, r.send)
	f.DrainAudit(audit(t0, 3), 500, r.send)
	if len(r.sizes) != 1 || r.sizes[0] != 3 {
		t.Fatalf("batches = %v, want a single batch of 3", r.sizes)
	}
	// New events after the watermark are sent.
	f.DrainAudit(audit(t0, 5), 500, r.send)
	if len(r.sizes) != 2 || r.sizes[1] != 2 {
		t.Fatalf("batches = %v, want a second batch of just the 2 new events", r.sizes)
	}
}

func TestBatchesAreOldestFirstAndResumeAfterATransientFailure(t *testing.T) {
	f := New("test", quiet())
	r := recorder{fail: func(call int) error {
		if call == 1 {
			return errors.New("connection refused")
		}
		return nil
	}}
	events := audit(t0, 12)
	f.DrainAudit(events, 5, r.send) // batch 0 (5) ok, batch 1 fails, stop
	if len(r.sizes) != 2 || r.first[0] != "p0" {
		t.Fatalf("first cycle: sizes=%v first=%v; want two attempts starting at the oldest event", r.sizes, r.first)
	}
	f.DrainAudit(events, 5, r.send) // resumes at p5: 7 left -> 5 + 2
	if got := r.sizes[2:]; len(got) != 2 || got[0] != 5 || got[1] != 2 {
		t.Fatalf("resume batches = %v, want [5 2]", got)
	}
	if r.first[2] != "p5" {
		t.Fatalf("resumed at %s, want p5 (no duplicate of the committed batch)", r.first[2])
	}
}

func TestATransientFailureDoesNotAdvanceTheWatermark(t *testing.T) {
	f := New("test", quiet())
	fail := true
	send := func(recs []siem.Record) error {
		if fail {
			return &StatusError{Code: 503, Body: "busy"}
		}
		return nil
	}
	f.DrainAudit(audit(t0, 4), 500, send)
	fail = false
	var r recorder
	f.DrainAudit(audit(t0, 4), 500, r.send)
	if len(r.sizes) != 1 || r.sizes[0] != 4 {
		t.Fatalf("retry batches = %v, want the same 4 events", r.sizes)
	}
}

// One malformed batch must not wedge the sink behind it forever.
func TestAPermanentlyRejectedBatchIsDroppedAndDeliveryContinues(t *testing.T) {
	var logs bytes.Buffer
	f := New("loki", slog.New(slog.NewTextHandler(&logs, nil)))
	r := recorder{fail: func(call int) error {
		if call == 0 {
			return &StatusError{Code: 400, Body: "entry too far behind"}
		}
		return nil
	}}
	events := audit(t0, 7)
	f.DrainAudit(events, 3, r.send)
	if len(r.sizes) != 3 || r.first[1] != "p3" || r.first[2] != "p6" {
		t.Fatalf("sizes=%v first=%v: after dropping batch 0 the rest must still be delivered in order", r.sizes, r.first)
	}
	if !strings.Contains(logs.String(), "dropping it") || !strings.Contains(logs.String(), "too far behind") {
		t.Fatalf("the drop must be logged with the reason: %s", logs.String())
	}
	// And the dropped events are not resent next cycle.
	before := len(r.sizes)
	f.DrainAudit(events, 3, r.send)
	if len(r.sizes) != before {
		t.Fatalf("a dropped batch was resent (%d extra sends)", len(r.sizes)-before)
	}
}

func TestOnlyMalformedStatusesArePermanent(t *testing.T) {
	for code, want := range map[int]bool{
		400: true, 413: true, 422: true, // the batch itself is bad
		401: false, 403: false, 404: false, // credentials or URL: fixable, keep the data
		408: false, 429: false, 500: false, 502: false, 503: false, 504: false, 307: false,
	} {
		if got := IsPermanent(&StatusError{Code: code}); got != want {
			t.Errorf("IsPermanent(%d) = %v, want %v", code, got, want)
		}
	}
	if IsPermanent(errors.New("dial tcp: refused")) || IsPermanent(nil) {
		t.Error("a transport error or nil is not permanent")
	}
	wrapped := fmt.Errorf("posting: %w", &StatusError{Code: 400})
	if !IsPermanent(wrapped) {
		t.Error("a wrapped 400 must still be recognised")
	}
}

// Agents stamp ObservedAt on their own clocks; one global cutoff would drop a
// lagging node's new events once a faster node had advanced it.
func TestBlockWatermarkIsPerNode(t *testing.T) {
	f := New("test", quiet())
	events := map[string][]models.FastPathEvent{
		"fast": {blockEv(t0.Add(time.Hour))},
		"slow": {blockEv(t0)},
	}
	var sent []string
	send := func(node string, recs []siem.Record) error {
		sent = append(sent, fmt.Sprintf("%s:%d", node, len(recs)))
		return nil
	}
	f.DrainBlocks(events, 500, send)
	events["slow"] = append(events["slow"], blockEv(t0.Add(time.Minute)))
	f.DrainBlocks(events, 500, send)
	if got := strings.Join(sent, " "); got != "fast:1 slow:1 slow:1" {
		t.Fatalf("sends = %q, want fast:1 slow:1 slow:1 (the slow node's newer-than-its-own event must ship)", got)
	}
}

func TestOneNodesFailureDoesNotBlockOthersAndItStaysBehind(t *testing.T) {
	f := New("test", quiet())
	events := map[string][]models.FastPathEvent{"a": {blockEv(t0)}, "b": {blockEv(t0)}}
	failA := true
	var sent []string
	send := func(node string, recs []siem.Record) error {
		if node == "a" && failA {
			return errors.New("timeout")
		}
		sent = append(sent, node)
		return nil
	}
	f.DrainBlocks(events, 500, send)
	failA = false
	f.DrainBlocks(events, 500, send)
	if got := strings.Join(sent, ","); got != "b,a" {
		t.Fatalf("delivered %q, want b first (a failed) then a on the retry, b not repeated", got)
	}
}

func TestOnlyBlockedTimestampedEventsAreSent(t *testing.T) {
	f := New("test", quiet())
	var n int
	f.DrainBlocks(map[string][]models.FastPathEvent{"n": {
		{ObservedAt: t0, Action: "allowed"},
		{Action: "blocked"}, // no timestamp: cannot be deduplicated
		blockEv(t0),
	}}, 500, func(node string, recs []siem.Record) error { n += len(recs); return nil })
	if n != 1 {
		t.Fatalf("sent %d events, want exactly the one blocked, timestamped event", n)
	}
}
