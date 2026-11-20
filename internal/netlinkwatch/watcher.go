// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package netlinkwatch records read-only Linux network control-plane state
// and changes. It never mutates links, addresses, routes, rules, neighbours,
// qdiscs, or any Cilium-owned object.
//
// Everything except the raw kernel calls (watcher_linux.go) lives here so the
// ring, the delivery cursor, the resubscribe supervisor and the snapshot caps
// are unit-testable on any OS.
package netlinkwatch

import (
	"cmp"
	"context"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// DefaultCapacity is the agent event ring size.
	DefaultCapacity = 4096
	// MaxCapacity bounds NETRA_NETLINK_EVENT_BUFFER.
	MaxCapacity = 1_000_000
	// MaxReportEvents bounds the events one report carries, so one noisy node
	// cannot inflate every agent report. The rest stay in the ring for the next.
	MaxReportEvents = 500

	// Snapshot list caps. A node with more entries ships the first N in sorted
	// order and reports the remainder in Snapshot.Truncated.
	maxSnapshotLinks     = 2000
	maxSnapshotAddresses = 4000
	maxSnapshotRoutes    = 4000
	maxSnapshotNeighbors = 4000

	// snapshotRefresh is how often an unchanged snapshot is re-shipped so a
	// controller that restarted (and lost its copy) recovers without waiting
	// for the network to change.
	snapshotRefresh = 5 * time.Minute

	defaultBackoff = 500 * time.Millisecond
	maxBackoff     = 30 * time.Second
	stableAfter    = time.Minute
	maxDetail      = 200
)

// Watcher owns a bounded, process-local change ring and the latest full
// kernel snapshot. Periodic resnapshotting heals lost multicast messages and
// makes recovery explicit through ResyncedAt.
type Watcher struct {
	mu       sync.RWMutex
	epoch    int64
	capacity int
	ring     []models.NetlinkEvent
	head     int
	size     int
	next     uint64

	dropped      uint64
	overruns     uint64
	resubscribes uint64
	suppressed   uint64
	totals       map[string]uint64

	generation uint64
	resyncs    uint64
	snapshot   models.NetlinkSnapshot
	counts     models.NetlinkCounts
	names      map[int]string
	neighbors  map[string]string
	errors     map[string]string

	// Delivery state: the agent reports, and only after the controller accepted
	// the report does Commit advance these. A failed POST resends the events.
	acked   uint64
	missed  uint64
	sentGen uint64
	sentAt  time.Time

	// attr, when set, says who requested each change (bpf/netra_rtnl.c); events are
	// attributed on the copies a report carries, never in the ring, so a resent
	// event is attributed again and the ring stays the raw record.
	attr        Attributor
	attrGrace   time.Duration
	actorWhy    string
	resync      chan struct{}
	backoffBase time.Duration
	now         func() time.Time
	stop        context.CancelFunc
}

// Attributor joins a recorded change to the request that caused it.
type Attributor interface {
	// Attribute returns the requester (nil when none is named) and the change's
	// origin: "process", "kernel", or "" when that cannot be told.
	Attribute(models.NetlinkEvent) (*models.NetlinkActor, string)
	Status() models.NetlinkActorStatus
}

// SetAttributor turns attribution on. Events younger than grace are held back from
// reports until their request record has had time to arrive, since the request is
// read from the kernel independently of the change notification.
func (w *Watcher) SetAttributor(a Attributor, grace time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.attr, w.attrGrace, w.actorWhy = a, grace, ""
}

// SetActorUnavailable records why attribution could not start, so a report says
// "unavailable" instead of saying nothing.
func (w *Watcher) SetActorUnavailable(why string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.attr, w.actorWhy = nil, why
}

func newWatcher(capacity int) *Watcher {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if capacity > MaxCapacity {
		capacity = MaxCapacity
	}
	return &Watcher{
		epoch:       time.Now().UnixNano(),
		capacity:    capacity,
		ring:        make([]models.NetlinkEvent, capacity),
		totals:      map[string]uint64{},
		names:       map[int]string{},
		neighbors:   map[string]string{},
		errors:      map[string]string{},
		resync:      make(chan struct{}, 1),
		backoffBase: defaultBackoff,
		now:         func() time.Time { return time.Now().UTC() },
	}
}

// Close stops all subscriptions. It is safe to call more than once.
func (w *Watcher) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	stop := w.stop
	w.stop = nil
	w.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// append stores one event, assigning its sequence and epoch, and fills in the
// interface name from the ifindex cache when the kernel message carried none
// (address, route and neighbor messages carry only the index).
func (w *Watcher) append(e models.NetlinkEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.next++
	e.Sequence = w.next
	e.Epoch = w.epoch
	if e.ObservedAt.IsZero() {
		e.ObservedAt = w.now()
	}
	if e.Kind == models.NetlinkKindLink && e.Action == "new" && e.InterfaceIndex > 0 && e.Interface != "" {
		w.names[e.InterfaceIndex] = e.Interface
	}
	if e.Interface == "" && e.InterfaceIndex > 0 {
		e.Interface = w.names[e.InterfaceIndex]
	}
	w.totals[e.Kind]++
	w.ring[(w.head+w.size)%w.capacity] = e
	if w.size == w.capacity {
		w.head = (w.head + 1) % w.capacity
		w.dropped++
		return
	}
	w.size++
}

// recordNeighbor stores a neighbor change unless it is routine NUD churn. The
// kernel emits RTM_NEWNEIGH for every reachable/stale/delay/probe transition,
// which would evict the changes that matter; only first sight, deletion and a
// move into failed/incomplete are recorded. The rest are counted.
func (w *Watcher) recordNeighbor(e models.NetlinkEvent) {
	key := strconv.Itoa(e.InterfaceIndex) + "|" + e.Address
	w.mu.Lock()
	if e.Action == "delete" {
		delete(w.neighbors, key)
	} else {
		prev, seen := w.neighbors[key]
		w.neighbors[key] = e.State
		bad := strings.Contains(e.State, "failed") || strings.Contains(e.State, "incomplete")
		if seen && (!bad || prev == e.State) {
			w.suppressed++
			w.mu.Unlock()
			return
		}
	}
	w.mu.Unlock()
	w.append(e)
}

// recordOverrun notes that kernel messages or a whole subscription were lost,
// and reports whether the cause was a kernel receive-buffer overflow (ENOBUFS).
func (w *Watcher) recordOverrun(sensor, why string) (overflow bool) {
	overflow = strings.Contains(strings.ToLower(why), "no buffer space")
	if len(why) > maxDetail {
		why = why[:maxDetail]
	}
	w.mu.Lock()
	w.resubscribes++
	if overflow {
		w.overruns++
	}
	w.mu.Unlock()
	w.append(models.NetlinkEvent{Kind: models.NetlinkKindOverrun, Action: "lost", Detail: sensor + ": " + why})
	w.requestResync()
	return overflow
}

func (w *Watcher) requestResync() {
	select {
	case w.resync <- struct{}{}:
	default:
	}
}

func (w *Watcher) setError(sensor string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err == nil {
		delete(w.errors, sensor)
		return
	}
	w.errors[sensor] = err.Error()
}

// setSnapshot installs a freshly collected full snapshot. The generation only
// advances when the content changed, so an idle node does not re-ship it.
func (w *Watcher) setSnapshot(full models.NetlinkSnapshot) {
	names := make(map[int]string, len(full.Links))
	for _, l := range full.Links {
		names[l.Index] = l.Name
	}
	neighbors := make(map[string]string, len(full.Neighbors))
	counts := models.NetlinkCounts{
		Links: len(full.Links), Addresses: len(full.Addresses),
		Routes: len(full.Routes), Neighbors: len(full.Neighbors),
	}
	prevStates := func(key, state string, old map[string]string) string {
		if s, ok := old[key]; ok {
			return s
		}
		return state
	}
	s := capSnapshot(full)

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, n := range full.Neighbors {
		key := strconv.Itoa(n.InterfaceIndex) + "|" + n.Address
		neighbors[key] = prevStates(key, n.State, w.neighbors)
	}
	s.ResyncedAt = w.now()
	old := w.snapshot
	old.ResyncedAt = s.ResyncedAt
	if w.generation == 0 || !reflect.DeepEqual(old, s) {
		w.generation++
	}
	w.snapshot = s
	w.counts = counts
	w.names = names
	w.neighbors = neighbors
	w.resyncs++
}

// capSnapshot sorts every list deterministically and bounds it.
func capSnapshot(in models.NetlinkSnapshot) models.NetlinkSnapshot {
	slices.SortFunc(in.Links, func(a, b models.NetlinkLink) int { return cmp.Compare(a.Index, b.Index) })
	slices.SortFunc(in.Addresses, func(a, b models.NetlinkAddress) int {
		return cmp.Or(cmp.Compare(a.Interface, b.Interface), cmp.Compare(a.Address, b.Address))
	})
	slices.SortFunc(in.Routes, func(a, b models.NetlinkRoute) int {
		return cmp.Or(
			cmp.Compare(a.Family, b.Family), cmp.Compare(a.Table, b.Table),
			cmp.Compare(a.Destination, b.Destination), cmp.Compare(a.Priority, b.Priority),
			cmp.Compare(a.InterfaceIndex, b.InterfaceIndex), cmp.Compare(a.Gateway, b.Gateway),
			cmp.Compare(a.Source, b.Source),
		)
	})
	slices.SortFunc(in.Neighbors, func(a, b models.NetlinkNeighbor) int {
		return cmp.Or(cmp.Compare(a.Interface, b.Interface), cmp.Compare(a.Address, b.Address))
	})
	in.Truncated = models.NetlinkCounts{}
	in.Links, in.Truncated.Links = capList(in.Links, maxSnapshotLinks)
	in.Addresses, in.Truncated.Addresses = capList(in.Addresses, maxSnapshotAddresses)
	in.Routes, in.Truncated.Routes = capList(in.Routes, maxSnapshotRoutes)
	in.Neighbors, in.Truncated.Neighbors = capList(in.Neighbors, maxSnapshotNeighbors)
	return in
}

func capList[T any](in []T, limit int) ([]T, int) {
	if len(in) <= limit {
		return in, 0
	}
	return in[:limit:limit], len(in) - limit
}

// Report returns the events not yet acknowledged (oldest first, at most limit)
// and the state summary. The full snapshot is attached only when it changed
// since the last acknowledged report or is due for a periodic refresh. Nothing
// advances until Commit, so a failed delivery resends the same events.
func (w *Watcher) Report(limit int) models.NetlinkReport {
	if w == nil {
		return models.NetlinkReport{Unavailable: "netlink watcher disabled"}
	}
	if limit <= 0 || limit > MaxReportEvents {
		limit = MaxReportEvents
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := models.NetlinkReport{
		Available: true, Epoch: w.epoch, Sequence: w.next, Cursor: w.acked,
		Dropped: w.dropped, Missed: w.missed, Overruns: w.overruns,
		Resubscribes: w.resubscribes, Suppressed: w.suppressed,
		Generation: w.generation, ResyncedAt: w.snapshot.ResyncedAt, Counts: w.counts,
		Error: w.errorTextLocked(),
	}
	if len(w.totals) > 0 {
		out.Totals = maps.Clone(w.totals)
	}
	if w.size > 0 {
		if first := w.ring[w.head].Sequence; first > w.acked+1 {
			out.Missed += first - w.acked - 1 // overwritten before delivery
		}
	}
	for i := 0; i < w.size && len(out.Events) < limit; i++ {
		e := w.ring[(w.head+i)%w.capacity]
		if e.Sequence <= w.acked {
			continue
		}
		if w.attr != nil {
			// Oldest first, so everything after this is younger still: wait for the
			// request record of a change that only just happened.
			if w.now().Sub(e.ObservedAt) < w.attrGrace {
				break
			}
			e.Actor, e.Origin = w.attr.Attribute(e)
		}
		out.Events = append(out.Events, e)
		out.Cursor = e.Sequence
	}
	switch {
	case w.attr != nil:
		st := w.attr.Status()
		out.Actor = &st
	case w.actorWhy != "":
		out.Actor = &models.NetlinkActorStatus{Unavailable: w.actorWhy}
	}
	if w.generation > 0 && (w.generation != w.sentGen || w.sentAt.IsZero() || w.now().Sub(w.sentAt) >= snapshotRefresh) {
		s := w.snapshot
		s.Links = slices.Clone(s.Links)
		s.Addresses = slices.Clone(s.Addresses)
		s.Routes = slices.Clone(s.Routes)
		s.Neighbors = slices.Clone(s.Neighbors)
		out.Snapshot = &s
	}
	return out
}

// Commit records that the controller accepted r, so its events are not sent
// again and its snapshot (if any) counts as delivered.
func (w *Watcher) Commit(r models.NetlinkReport) {
	if w == nil || r.Epoch != w.epoch {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if r.Cursor > w.acked {
		w.acked = r.Cursor
	}
	if r.Missed > w.missed {
		w.missed = r.Missed
	}
	if r.Snapshot != nil {
		w.sentGen = r.Generation
		w.sentAt = w.now()
	}
}

func (w *Watcher) errorTextLocked() string {
	if len(w.errors) == 0 {
		return ""
	}
	keys := make([]string, 0, len(w.errors))
	for k := range w.errors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+w.errors[k])
	}
	return strings.Join(parts, "; ")
}

// startFunc opens one kernel subscription. It returns a channel that closes
// when the subscription ends and a function giving the last error the kernel
// side reported for it (the library reports errors only through a callback).
type startFunc func(ctx context.Context) (closed <-chan struct{}, lastErr func() string, err error)

// supervise keeps one subscription alive. The netlink library closes its
// channel on any receive error, ENOBUFS included, and never reopens it, so a
// single route storm would otherwise blind the recorder until the agent
// restarted. Each loss is recorded as an overrun event, a resnapshot is
// requested to heal current state, and the subscription is reopened with a
// capped backoff.
func (w *Watcher) supervise(ctx context.Context, sensor string, start startFunc) {
	delay := w.backoffBase
	for {
		subCtx, cancel := context.WithCancel(ctx)
		began := time.Now()
		closed, lastErr, err := start(subCtx)
		if err != nil {
			cancel()
			w.setError(sensor+"-subscribe", err)
		} else {
			w.setError(sensor+"-subscribe", nil)
			select {
			case <-ctx.Done():
				cancel()
				return
			case <-closed:
			}
			cancel()
			if ctx.Err() != nil {
				return
			}
			why := lastErr()
			if why == "" {
				why = "subscription closed"
			}
			overflow := w.recordOverrun(sensor, why)
			w.setError(sensor+"-subscribe", &lostError{why})
			// A receive-buffer overflow means the socket worked and the reader was
			// slow, not that subscribing is failing, so it reopens at once. Backing
			// off there would blind the recorder for up to maxBackoff during a
			// sustained storm, which is exactly when changes matter. Failed starts
			// and other losses still back off, unless the subscription had been
			// stable for a while.
			if overflow || time.Since(began) > stableAfter {
				delay = w.backoffBase
			}
		}
		if !sleepCtx(ctx, delay) {
			return
		}
		delay = min(delay*2, maxBackoff)
	}
}

type lostError struct{ why string }

func (e *lostError) Error() string { return "subscription lost (" + e.why + "); re-establishing" }

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// refresh takes one full snapshot.
func (w *Watcher) refresh(collect func() (models.NetlinkSnapshot, error)) error {
	s, err := collect()
	if err != nil {
		w.setError("snapshot", err)
		return err
	}
	w.setError("snapshot", nil)
	w.setSnapshot(s)
	return nil
}

// runSnapshots re-collects the full state every interval and whenever a loss
// asks for one.
func (w *Watcher) runSnapshots(ctx context.Context, collect func() (models.NetlinkSnapshot, error), every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.resync:
		}
		_ = w.refresh(collect)
	}
}
