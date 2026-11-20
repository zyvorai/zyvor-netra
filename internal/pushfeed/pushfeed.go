// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package pushfeed is the delivery logic shared by Netra's push sinks (OTLP,
// Loki): which audit and block events are new since the last successful send,
// how they are batched, and what a failed send means.
//
// A sink supplies only "encode and POST these records". pushfeed guarantees
// the rest:
//
//   - Watermarks advance only past batches that were delivered (or that can
//     never be delivered), so a transient failure resends the same events
//     next cycle and nothing is skipped.
//   - Block-event watermarks are per node: agents stamp events on their own
//     clocks, so one global cutoff would drop a slower node's events once a
//     faster node had advanced it.
//   - A batch the destination rejects as malformed (HTTP 400/413/422) can
//     never succeed, so it is dropped and the watermark moves on. Retrying it
//     forever would wedge the sink behind one poison batch. Everything else
//     (network errors, 5xx, 429, auth failures) is retried next cycle.
package pushfeed

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/siem"
)

// StatusError is a destination's non-success HTTP answer.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Code, strings.TrimSpace(e.Body))
}

// IsPermanent reports whether err says the batch itself is unacceptable and
// resending it unchanged cannot help.
func IsPermanent(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case 400, 413, 422:
		return true
	}
	return false
}

// Send delivers one oldest-first batch. It returns nil on success, a
// *StatusError for an HTTP refusal, or any other error for a transport failure.
type Send func(recs []siem.Record) error

// SendNode is Send for one node's block events.
type SendNode func(node string, recs []siem.Record) error

// Feed tracks what has already been delivered. The zero value is not usable;
// call New.
type Feed struct {
	sink string
	log  *slog.Logger

	mu      sync.Mutex
	auditAt time.Time
	blockAt map[string]time.Time
}

// New returns a Feed; sink names the destination in log lines.
func New(sink string, log *slog.Logger) *Feed {
	if log == nil {
		log = slog.Default()
	}
	return &Feed{sink: sink, log: log, blockAt: map[string]time.Time{}}
}

// DrainAudit delivers audit events newer than the watermark, oldest first, in
// batches of at most maxBatch. events is a newest-first snapshot, as
// store.Audit returns.
func (f *Feed) DrainAudit(events []models.AuditEvent, maxBatch int, send Send) {
	f.mu.Lock()
	cutoff := f.auditAt
	f.mu.Unlock()

	fresh, _ := siem.NewSince(events, cutoff)
	for len(fresh) > 0 {
		n := min(len(fresh), maxBatch)
		batch := fresh[:n]
		recs := make([]siem.Record, len(batch))
		for i, e := range batch {
			recs[i] = siem.FromAudit(e)
		}
		if !f.settle("audit", "", len(fresh), len(batch), send(recs)) {
			return
		}
		// fresh is oldest-first, so the batch's last element is its newest.
		f.mu.Lock()
		if at := batch[len(batch)-1].At; at.After(f.auditAt) {
			f.auditAt = at
		}
		f.mu.Unlock()
		fresh = fresh[n:]
	}
}

// DrainBlocks delivers block/deny events newer than each node's watermark.
// Events without a timestamp cannot be deduplicated and are skipped.
func (f *Feed) DrainBlocks(byNode map[string][]models.FastPathEvent, maxBatch int, send SendNode) {
	nodes := make([]string, 0, len(byNode))
	for n := range byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	for _, node := range nodes {
		f.mu.Lock()
		cutoff := f.blockAt[node]
		f.mu.Unlock()

		var fresh []models.FastPathEvent
		for _, ev := range byNode[node] {
			if ev.ObservedAt.IsZero() || !siem.IsBlocked(ev.Action) {
				continue
			}
			if !cutoff.IsZero() && !ev.ObservedAt.After(cutoff) {
				continue
			}
			fresh = append(fresh, ev)
		}
		sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].ObservedAt.Before(fresh[j].ObservedAt) })

		for len(fresh) > 0 {
			n := min(len(fresh), maxBatch)
			batch := fresh[:n]
			recs := make([]siem.Record, len(batch))
			for i, ev := range batch {
				recs[i] = siem.FromBlockEvent(node, ev)
			}
			if !f.settle("block", node, len(fresh), len(batch), send(node, recs)) {
				break // this node stays behind; other nodes are independent
			}
			f.mu.Lock()
			if at := batch[len(batch)-1].ObservedAt; at.After(f.blockAt[node]) {
				f.blockAt[node] = at
			}
			f.mu.Unlock()
			fresh = fresh[n:]
		}
	}
}

// settle interprets a send result. It returns true when the batch is done with
// (delivered, or permanently unacceptable) and the watermark may advance.
func (f *Feed) settle(kind, node string, pending, batch int, err error) bool {
	switch {
	case err == nil:
		return true
	case IsPermanent(err):
		f.log.Warn("push sink rejected a batch as unacceptable; dropping it",
			"sink", f.sink, "kind", kind, "node", node, "events", batch, "error", err)
		return true
	default:
		f.log.Warn("push failed; will retry next cycle",
			"sink", f.sink, "kind", kind, "node", node, "pending", pending, "error", err)
		return false
	}
}

// ParseKeyValues reads "k1=v1,k2=v2" (the OTEL_EXPORTER_OTLP_HEADERS shape),
// used for request headers and static labels. what names the setting in errors.
func ParseKeyValues(s, what string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("%s must be comma-separated key=value pairs", what)
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}
