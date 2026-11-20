// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package netlinkwatch

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func link(name string) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: name}
}

func TestRingIsBoundedAndCursorBased(t *testing.T) {
	w := newWatcher(3)
	for _, n := range []string{"eth0", "eth1", "eth2", "eth3"} {
		w.append(link(n))
	}
	r := w.Report(100)
	if r.Sequence != 4 || r.Dropped != 1 {
		t.Fatalf("sequence=%d dropped=%d", r.Sequence, r.Dropped)
	}
	if len(r.Events) != 3 || r.Events[0].Interface != "eth1" || r.Events[2].Interface != "eth3" || r.Cursor != 4 {
		t.Fatalf("events=%#v cursor=%d", r.Events, r.Cursor)
	}
	// eth0 (seq 1) was overwritten before anything was delivered.
	if r.Missed != 1 {
		t.Fatalf("missed=%d, want 1", r.Missed)
	}
	if r.Epoch == 0 || r.Events[0].Epoch != r.Epoch {
		t.Fatalf("epoch not stamped: report=%d event=%d", r.Epoch, r.Events[0].Epoch)
	}
}

func TestFailedDeliveryResendsUntilCommitted(t *testing.T) {
	w := newWatcher(8)
	w.append(link("a"))
	w.append(link("b"))
	first := w.Report(100)
	// The POST failed: no Commit. The same events must come back.
	again := w.Report(100)
	if len(first.Events) != 2 || len(again.Events) != 2 || again.Events[0].Sequence != 1 {
		t.Fatalf("events lost without a commit: %#v", again.Events)
	}
	w.Commit(first)
	w.append(link("c"))
	next := w.Report(100)
	if len(next.Events) != 1 || next.Events[0].Interface != "c" || next.Cursor != 3 {
		t.Fatalf("after commit: %#v cursor=%d", next.Events, next.Cursor)
	}
}

func TestReportLimitDeliversOldestFirstAndContinues(t *testing.T) {
	w := newWatcher(10)
	for range 5 {
		w.append(link("x"))
	}
	r := w.Report(2)
	if len(r.Events) != 2 || r.Events[0].Sequence != 1 || r.Cursor != 2 || r.Missed != 0 {
		t.Fatalf("first page: %#v cursor=%d missed=%d", r.Events, r.Cursor, r.Missed)
	}
	w.Commit(r)
	r = w.Report(10)
	if len(r.Events) != 3 || r.Events[0].Sequence != 3 || r.Missed != 0 {
		t.Fatalf("second page: %#v missed=%d", r.Events, r.Missed)
	}
}

func TestCommitIgnoresAnotherEpoch(t *testing.T) {
	w := newWatcher(4)
	w.append(link("a"))
	r := w.Report(10)
	r.Epoch++
	w.Commit(r)
	if got := w.Report(10); len(got.Events) != 1 {
		t.Fatalf("a foreign report advanced the cursor: %#v", got.Events)
	}
}

func TestEventsGetInterfaceNameFromIndexCache(t *testing.T) {
	w := newWatcher(8)
	w.append(models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", InterfaceIndex: 7, Interface: "veth7"})
	w.append(models.NetlinkEvent{Kind: models.NetlinkKindRoute, Action: "delete", InterfaceIndex: 7, Destination: "10.0.0.0/24"})
	// A deleted link's name is still resolvable for the events that follow it.
	w.append(models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "delete", InterfaceIndex: 7, Interface: "veth7"})
	w.append(models.NetlinkEvent{Kind: models.NetlinkKindAddress, Action: "delete", InterfaceIndex: 7, Address: "10.0.0.1/24"})
	ev := w.Report(10).Events
	if ev[1].Interface != "veth7" || ev[3].Interface != "veth7" {
		t.Fatalf("names not resolved: %#v", ev)
	}
}

func TestNeighborChurnIsSuppressedButFailuresAreKept(t *testing.T) {
	w := newWatcher(16)
	n := func(action, state string) models.NetlinkEvent {
		return models.NetlinkEvent{Kind: models.NetlinkKindNeighbor, Action: action, InterfaceIndex: 2, Address: "10.0.0.1", State: state}
	}
	w.recordNeighbor(n("new", "reachable")) // first sight: kept
	w.recordNeighbor(n("new", "stale"))     // churn
	w.recordNeighbor(n("new", "delay"))     // churn
	w.recordNeighbor(n("new", "probe"))     // churn
	w.recordNeighbor(n("new", "reachable")) // churn
	w.recordNeighbor(n("new", "failed"))    // failure: kept
	w.recordNeighbor(n("new", "failed"))    // same failure again: suppressed
	w.recordNeighbor(n("delete", "failed")) // removal: kept
	r := w.Report(100)
	if len(r.Events) != 3 {
		t.Fatalf("recorded %d neighbor events, want 3: %#v", len(r.Events), r.Events)
	}
	if r.Events[1].State != "failed" || r.Events[2].Action != "delete" {
		t.Fatalf("unexpected events: %#v", r.Events)
	}
	if r.Suppressed != 5 {
		t.Fatalf("suppressed=%d, want 5", r.Suppressed)
	}
}

func TestSnapshotGenerationOnlyAdvancesOnChange(t *testing.T) {
	w := newWatcher(4)
	snap := func(mtu int) models.NetlinkSnapshot {
		return models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 2, Name: "eth0", MTU: mtu}}}
	}
	w.setSnapshot(snap(1500))
	g1 := w.Report(1).Generation
	w.setSnapshot(snap(1500)) // identical content, new ResyncedAt
	if g := w.Report(1).Generation; g != g1 {
		t.Fatalf("generation moved on an unchanged snapshot: %d -> %d", g1, g)
	}
	w.setSnapshot(snap(9000))
	if g := w.Report(1).Generation; g != g1+1 {
		t.Fatalf("generation did not move on a change: %d -> %d", g1, g)
	}
}

func TestSnapshotShipsOnlyWhenChangedOrDue(t *testing.T) {
	w := newWatcher(4)
	clock := time.Unix(1_000, 0).UTC()
	w.now = func() time.Time { return clock }
	if w.Report(1).Snapshot != nil {
		t.Fatal("a snapshot was shipped before one was taken")
	}
	w.setSnapshot(models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 1, Name: "lo"}}})
	r := w.Report(1)
	if r.Snapshot == nil {
		t.Fatal("first snapshot not shipped")
	}
	w.Commit(r)
	if w.Report(1).Snapshot != nil {
		t.Fatal("unchanged snapshot re-shipped right after delivery")
	}
	clock = clock.Add(snapshotRefresh + time.Second)
	if w.Report(1).Snapshot == nil {
		t.Fatal("snapshot not refreshed after the refresh interval")
	}
	// A failed delivery must not count as sent.
	w2 := newWatcher(4)
	w2.setSnapshot(models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 1, Name: "lo"}}})
	_ = w2.Report(1)
	if w2.Report(1).Snapshot == nil {
		t.Fatal("snapshot dropped without a commit")
	}
}

func TestSnapshotIsSortedCappedAndCloned(t *testing.T) {
	w := newWatcher(1)
	var routes []models.NetlinkRoute
	for i := range maxSnapshotRoutes + 25 {
		routes = append(routes, models.NetlinkRoute{Family: "ipv4", Table: 254, Destination: net.IPv4(10, byte(i>>8), byte(i), 0).String() + "/24"})
	}
	w.setSnapshot(models.NetlinkSnapshot{
		Links:  []models.NetlinkLink{{Index: 3, Name: "b"}, {Index: 1, Name: "a"}},
		Routes: routes,
	})
	r := w.Report(1)
	if r.Counts.Routes != maxSnapshotRoutes+25 || r.Snapshot.Truncated.Routes != 25 || len(r.Snapshot.Routes) != maxSnapshotRoutes {
		t.Fatalf("counts=%+v truncated=%+v kept=%d", r.Counts, r.Snapshot.Truncated, len(r.Snapshot.Routes))
	}
	if r.Snapshot.Links[0].Name != "a" {
		t.Fatalf("links not sorted: %#v", r.Snapshot.Links)
	}
	r.Snapshot.Links[0].Name = "mutated"
	if got := w.Report(1).Snapshot.Links[0].Name; got != "a" {
		t.Fatalf("internal snapshot was mutated: %q", got)
	}
}

func TestErrorsAreStableAndSorted(t *testing.T) {
	w := newWatcher(1)
	w.setError("route", errors.New("route failed"))
	w.setError("address", errors.New("address failed"))
	if got := w.Report(1).Error; got != "address: address failed; route: route failed" {
		t.Fatalf("error=%q", got)
	}
	w.setError("address", nil)
	if got := w.Report(1).Error; got != "route: route failed" {
		t.Fatalf("error after clear=%q", got)
	}
}

func TestNilWatcherReportsUnavailable(t *testing.T) {
	var w *Watcher
	if r := w.Report(1); r.Available || r.Unavailable == "" {
		t.Fatalf("nil watcher: %#v", r)
	}
	w.Commit(models.NetlinkReport{}) // must not panic
	w.Close()
}

// The library closes a subscription's channel on ENOBUFS and never reopens it.
// The supervisor must record the loss, ask for a resnapshot and reopen.
func TestSuperviseReopensAfterOverrun(t *testing.T) {
	w := newWatcher(16)
	w.backoffBase = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var starts atomic.Int32
	start := func(ctx context.Context) (<-chan struct{}, func() string, error) {
		n := starts.Add(1)
		closed := make(chan struct{})
		if n == 1 {
			close(closed) // first subscription dies at once
			return closed, func() string { return "Receive failed: no buffer space available" }, nil
		}
		go func() { <-ctx.Done(); close(closed) }() // later ones live until cancelled
		return closed, func() string { return "" }, nil
	}
	go w.supervise(ctx, "route", start)

	deadline := time.After(2 * time.Second)
	for starts.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("subscription was not reopened")
		case <-time.After(time.Millisecond):
		}
	}
	r := w.Report(100)
	if r.Overruns != 1 || r.Resubscribes != 1 {
		t.Fatalf("overruns=%d resubscribes=%d", r.Overruns, r.Resubscribes)
	}
	var found bool
	for _, e := range r.Events {
		if e.Kind == models.NetlinkKindOverrun && e.Action == "lost" {
			found = true
		}
	}
	if !found || r.Totals[models.NetlinkKindOverrun] != 1 {
		t.Fatalf("no overrun event: %#v totals=%v", r.Events, r.Totals)
	}
	select {
	case <-w.resync:
	default:
		t.Fatal("no resnapshot was requested after the loss")
	}
}

// Sustained storms overflow repeatedly. Backing off after each one would leave
// the recorder blind for up to maxBackoff exactly when changes matter, so an
// overflow always reopens after the base delay.
func TestSuperviseDoesNotBackOffOnRepeatedOverflow(t *testing.T) {
	w := newWatcher(64)
	w.backoffBase = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var starts atomic.Int32
	start := func(context.Context) (<-chan struct{}, func() string, error) {
		starts.Add(1)
		closed := make(chan struct{})
		close(closed)
		return closed, func() string { return "Receive failed: no buffer space available" }, nil
	}
	go w.supervise(ctx, "route", start)
	// Fixed delay: ~8 starts in ~160ms. Doubling delay: the 7th start alone is >1.2s away.
	deadline := time.After(700 * time.Millisecond)
	for starts.Load() < 8 {
		select {
		case <-deadline:
			t.Fatalf("only %d reopens in 700ms: overflow is backing off", starts.Load())
		case <-time.After(time.Millisecond):
		}
	}
	if r := w.Report(1); r.Overruns < 7 {
		t.Fatalf("overruns=%d, want each overflow counted", r.Overruns)
	}
}

// Any other loss, or a start that keeps failing, is a faulty subscription and
// must still back off rather than spin.
func TestSuperviseStillBacksOffOnOtherLosses(t *testing.T) {
	w := newWatcher(64)
	w.backoffBase = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var starts atomic.Int32
	start := func(context.Context) (<-chan struct{}, func() string, error) {
		starts.Add(1)
		closed := make(chan struct{})
		close(closed)
		return closed, func() string { return "connection reset" }, nil
	}
	go w.supervise(ctx, "route", start)
	time.Sleep(300 * time.Millisecond)
	// Doubling from 20ms: starts at ~0, 20, 60, 140, 300ms. A fixed delay would be ~15.
	if n := starts.Load(); n > 8 {
		t.Fatalf("%d starts in 300ms: a non-overflow loss is not backing off", n)
	}
	if r := w.Report(1); r.Overruns != 0 || r.Resubscribes == 0 {
		t.Fatalf("overruns=%d resubscribes=%d: only ENOBUFS is an overrun", r.Overruns, r.Resubscribes)
	}
}

func TestSuperviseRetriesAFailedStartAndStopsOnCancel(t *testing.T) {
	w := newWatcher(4)
	w.backoffBase = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	var starts atomic.Int32
	done := make(chan struct{})
	start := func(context.Context) (<-chan struct{}, func() string, error) {
		starts.Add(1)
		return nil, nil, errors.New("operation not permitted")
	}
	go func() { w.supervise(ctx, "link", start); close(done) }()
	for starts.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	if got := w.Report(1).Error; got != "link-subscribe: operation not permitted" {
		t.Fatalf("error=%q", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervise did not stop on cancel")
	}
	if w.Report(1).Resubscribes != 0 {
		t.Fatal("a failed start was counted as a lost subscription")
	}
}

func TestRunSnapshotsResyncsOnRequestAndRecordsFailure(t *testing.T) {
	w := newWatcher(4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	collect := func() (models.NetlinkSnapshot, error) {
		if calls.Add(1) == 1 {
			return models.NetlinkSnapshot{}, errors.New("list links: boom")
		}
		return models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 1, Name: "lo"}}}, nil
	}
	go w.runSnapshots(ctx, collect, time.Hour)
	w.requestResync()
	deadline := time.After(2 * time.Second)
	for w.Report(1).Error == "" {
		select {
		case <-deadline:
			t.Fatal("snapshot failure not recorded")
		case <-time.After(time.Millisecond):
		}
	}
	w.requestResync()
	for w.Report(1).Generation == 0 {
		select {
		case <-deadline:
			t.Fatal("snapshot not retaken after a request")
		case <-time.After(time.Millisecond):
		}
	}
	if e := w.Report(1).Error; e != "" {
		t.Fatalf("error not cleared by a good snapshot: %q", e)
	}
}

func TestConvertHelpers(t *testing.T) {
	if got := neighborState(nudFailed); got != "failed" {
		t.Fatalf("failed=%q", got)
	}
	if got := neighborState(nudReachable | nudPermanent); got != "reachable,permanent" {
		t.Fatalf("combined=%q", got)
	}
	if got := neighborState(0); got != "none" {
		t.Fatalf("none=%q", got)
	}
	if familyName(familyV4) != "ipv4" || familyName(familyV6) != "ipv6" || familyName(9) != "family-9" {
		t.Fatal("family names")
	}
	if got := familyOfIPs(nil, net.ParseIP("fe80::1")); got != "ipv6" {
		t.Fatalf("family=%q", got)
	}
	if got := familyOfIPs(nil, nil); got != "" {
		t.Fatalf("family of nothing=%q", got)
	}
	if routeDestination(nil) != "default" {
		t.Fatal("nil destination should read as default")
	}
	_, n, _ := net.ParseCIDR("10.1.0.0/16")
	if routeDestination(n) != "10.1.0.0/16" {
		t.Fatalf("dst=%q", routeDestination(n))
	}
}

func TestCapacityIsClamped(t *testing.T) {
	if w := newWatcher(-5); w.capacity != DefaultCapacity {
		t.Fatalf("capacity=%d", w.capacity)
	}
	if w := newWatcher(MaxCapacity + 1); w.capacity != MaxCapacity {
		t.Fatalf("capacity=%d", w.capacity)
	}
}

type fakeAttributor struct {
	calls  int
	actors map[string]*models.NetlinkActor // by destination
	origin string
}

func (f *fakeAttributor) Attribute(e models.NetlinkEvent) (*models.NetlinkActor, string) {
	f.calls++
	if a, ok := f.actors[e.Destination]; ok {
		return a, models.NetlinkOriginProcess
	}
	return nil, f.origin
}
func (f *fakeAttributor) Status() models.NetlinkActorStatus {
	return models.NetlinkActorStatus{Available: true, Records: 7, Dropped: 1}
}

func routeEv(dst string) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: models.NetlinkKindRoute, Action: "new", Destination: dst}
}

func TestEventsAreAttributedOnTheReportedCopyNotInTheRing(t *testing.T) {
	w := newWatcher(8)
	clock := time.Unix(5_000, 0).UTC()
	w.now = func() time.Time { return clock }
	w.append(routeEv("10.1.0.0/24"))
	w.append(routeEv("10.2.0.0/24"))
	clock = clock.Add(time.Second)
	f := &fakeAttributor{actors: map[string]*models.NetlinkActor{"10.1.0.0/24": {Confidence: "probable", Comm: "calico-node"}}, origin: models.NetlinkOriginKernel}
	w.SetAttributor(f, 300*time.Millisecond)

	r := w.Report(10)
	if len(r.Events) != 2 {
		t.Fatalf("events=%d", len(r.Events))
	}
	if r.Events[0].Origin != models.NetlinkOriginProcess || r.Events[0].Actor == nil || r.Events[0].Actor.Comm != "calico-node" {
		t.Fatalf("first event=%+v", r.Events[0])
	}
	if r.Events[1].Origin != models.NetlinkOriginKernel || r.Events[1].Actor != nil {
		t.Fatalf("second event=%+v", r.Events[1])
	}
	// The ring itself stays raw: a failed delivery resends and is attributed again.
	if w.ring[0].Actor != nil || w.ring[0].Origin != "" {
		t.Fatal("the ring was mutated by attribution")
	}
	callsBefore := f.calls
	if again := w.Report(10); len(again.Events) != 2 || again.Events[0].Actor == nil {
		t.Fatalf("a resent event lost its attribution: %+v", again.Events)
	}
	if f.calls <= callsBefore {
		t.Fatal("a resent event was not re-attributed")
	}
	if r.Actor == nil || !r.Actor.Available || r.Actor.Records != 7 {
		t.Fatalf("the report must carry the sensor's status: %+v", r.Actor)
	}
}

func TestAYoungEventWaitsForItsRequestRecord(t *testing.T) {
	w := newWatcher(8)
	clock := time.Unix(5_000, 0).UTC()
	w.now = func() time.Time { return clock }
	w.SetAttributor(&fakeAttributor{}, 300*time.Millisecond)
	w.append(routeEv("10.1.0.0/24"))
	clock = clock.Add(100 * time.Millisecond)
	w.append(routeEv("10.2.0.0/24"))
	clock = clock.Add(250 * time.Millisecond) // first is 350 ms old, second 250 ms

	r := w.Report(10)
	if len(r.Events) != 1 || r.Events[0].Destination != "10.1.0.0/24" || r.Cursor != 1 {
		t.Fatalf("only the event past the grace period may go out: %+v cursor=%d", r.Events, r.Cursor)
	}
	if r.Sequence != 2 {
		t.Fatalf("sequence=%d: the held-back event is still pending", r.Sequence)
	}
	w.Commit(r)
	clock = clock.Add(100 * time.Millisecond)
	if next := w.Report(10); len(next.Events) != 1 || next.Events[0].Destination != "10.2.0.0/24" {
		t.Fatalf("the held-back event must follow: %+v", next.Events)
	}
}

func TestWithoutAnAttributorEventsAreUntouchedAndUnheld(t *testing.T) {
	w := newWatcher(4)
	w.append(routeEv("10.1.0.0/24"))
	r := w.Report(10)
	if len(r.Events) != 1 || r.Events[0].Origin != "" || r.Events[0].Actor != nil || r.Actor != nil {
		t.Fatalf("report=%+v", r)
	}
}

func TestAnUnavailableSensorIsSaidInsteadOfSilent(t *testing.T) {
	w := newWatcher(4)
	w.SetActorUnavailable("kernel BTF is not available")
	r := w.Report(1)
	if r.Actor == nil || r.Actor.Available || r.Actor.Unavailable != "kernel BTF is not available" {
		t.Fatalf("actor=%+v", r.Actor)
	}
	w.append(routeEv("10.1.0.0/24"))
	if ev := w.Report(10).Events; len(ev) != 1 || ev[0].Origin != "" {
		t.Fatalf("without a sensor no origin may be claimed: %+v", ev)
	}
}
