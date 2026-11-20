// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package netlinkwatch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// These tests drive a real kernel: they create a veth pair and change its
// addresses, routes, neighbors and MTU. They need root, and they must run in a
// throwaway network namespace so they cannot touch the host's network:
//
//	scripts/ci-netlink-veth.sh   (ip netns exec ... with NETRA_NETLINK_KERNEL_TESTS=1)
//
// Without that variable they skip, so `go test ./...` never mutates the host.
func kernelTestGuard(t *testing.T) {
	t.Helper()
	if os.Getenv("NETRA_NETLINK_KERNEL_TESTS") != "1" {
		t.Skip("set NETRA_NETLINK_KERNEL_TESTS=1 and run in a network namespace (scripts/ci-netlink-veth.sh)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func ipCmd(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// sawEvent reports whether the ring holds an event matching pred.
func sawEvent(w *Watcher, pred func(models.NetlinkEvent) bool) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for i := 0; i < w.size; i++ {
		if pred(w.ring[(w.head+i)%w.capacity]) {
			return true
		}
	}
	return false
}

func TestKernelRecordsControlPlaneChanges(t *testing.T) {
	kernelTestGuard(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, err := Start(ctx, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.Report(1).Generation == 0 {
		t.Fatal("Start must take an initial snapshot")
	}

	ipCmd(t, "link", "add", "nlv0", "type", "veth", "peer", "name", "nlv1")
	ipCmd(t, "addr", "add", "10.99.0.1/24", "dev", "nlv0")
	ipCmd(t, "link", "set", "nlv0", "up")
	ipCmd(t, "link", "set", "nlv1", "up")
	ipCmd(t, "route", "add", "10.98.0.0/24", "via", "10.99.0.2", "dev", "nlv0")
	ipCmd(t, "neigh", "add", "10.99.0.9", "lladdr", "02:00:00:00:00:09", "dev", "nlv0", "nud", "permanent")
	ipCmd(t, "link", "set", "nlv0", "mtu", "1400")

	expect := func(what string, pred func(models.NetlinkEvent) bool) {
		t.Helper()
		waitFor(t, what, 10*time.Second, func() bool { return sawEvent(w, pred) })
	}
	expect("link new nlv0", func(e models.NetlinkEvent) bool {
		return e.Kind == "link" && e.Action == "new" && e.Interface == "nlv0" && e.LinkType == "veth"
	})
	expect("address new on nlv0 (name resolved from the ifindex cache)", func(e models.NetlinkEvent) bool {
		return e.Kind == "address" && e.Action == "new" && e.Address == "10.99.0.1/24" && e.Interface == "nlv0" && e.Family == "ipv4"
	})
	expect("route new via the gateway", func(e models.NetlinkEvent) bool {
		return e.Kind == "route" && e.Action == "new" && e.Destination == "10.98.0.0/24" &&
			e.Gateway == "10.99.0.2" && e.Interface == "nlv0"
	})
	expect("permanent neighbor with its MAC", func(e models.NetlinkEvent) bool {
		return e.Kind == "neighbor" && e.Action == "new" && e.Address == "10.99.0.9" && e.MAC == "02:00:00:00:00:09"
	})
	expect("MTU change to 1400", func(e models.NetlinkEvent) bool {
		return e.Kind == "link" && e.Interface == "nlv0" && e.MTU == 1400
	})

	// A resync must reflect the same objects in the full snapshot.
	w.requestResync()
	waitFor(t, "snapshot to contain the new objects", 10*time.Second, func() bool {
		s := w.Report(1).Snapshot
		if s == nil {
			return false
		}
		var link, addr, route, neigh bool
		for _, l := range s.Links {
			link = link || (l.Name == "nlv0" && l.MTU == 1400)
		}
		for _, a := range s.Addresses {
			addr = addr || (a.Interface == "nlv0" && a.Address == "10.99.0.1/24")
		}
		for _, r := range s.Routes {
			route = route || (r.Destination == "10.98.0.0/24" && r.Gateway == "10.99.0.2" && r.Interface == "nlv0")
		}
		for _, n := range s.Neighbors {
			neigh = neigh || (n.Address == "10.99.0.9" && n.MAC == "02:00:00:00:00:09")
		}
		return link && addr && route && neigh
	})

	ipCmd(t, "route", "del", "10.98.0.0/24")
	ipCmd(t, "neigh", "del", "10.99.0.9", "dev", "nlv0")
	ipCmd(t, "addr", "del", "10.99.0.1/24", "dev", "nlv0")
	ipCmd(t, "link", "set", "nlv0", "down")
	ipCmd(t, "link", "del", "nlv0")
	expect("route delete", func(e models.NetlinkEvent) bool {
		return e.Kind == "route" && e.Action == "delete" && e.Destination == "10.98.0.0/24"
	})
	expect("neighbor delete", func(e models.NetlinkEvent) bool {
		return e.Kind == "neighbor" && e.Action == "delete" && e.Address == "10.99.0.9"
	})
	expect("address delete", func(e models.NetlinkEvent) bool {
		return e.Kind == "address" && e.Action == "delete" && e.Address == "10.99.0.1/24"
	})
	expect("link down", func(e models.NetlinkEvent) bool {
		return e.Kind == "link" && e.Interface == "nlv0" && e.State == "down"
	})
	expect("link delete", func(e models.NetlinkEvent) bool {
		return e.Kind == "link" && e.Action == "delete" && e.Interface == "nlv0"
	})

	r := w.Report(MaxReportEvents)
	var last uint64
	for _, e := range r.Events {
		if e.Sequence <= last || e.Epoch != r.Epoch || e.ObservedAt.IsZero() {
			t.Fatalf("event identity broken: %#v (last seq %d)", e, last)
		}
		last = e.Sequence
	}
	if r.Overruns != 0 {
		t.Fatalf("overruns=%d during a quiet, ordinary run", r.Overruns)
	}
}

// A route storm larger than the kernel receive buffer must be survived: the
// overflow is counted and recorded, the recorder resubscribes, and changes made
// afterwards are seen again. Before the supervisor, the first ENOBUFS ended the
// route subscription until the agent restarted.
func TestKernelSurvivesRouteStormOverrun(t *testing.T) {
	kernelTestGuard(t)
	oldBuf, oldHook := recvBuffer, drainHook
	recvBuffer = 2048 // the kernel clamps this to its minimum
	var slow atomic.Bool
	slow.Store(true)
	drainHook = func() {
		if slow.Load() {
			time.Sleep(2 * time.Millisecond)
		}
	}
	defer func() { recvBuffer, drainHook = oldBuf, oldHook }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, err := Start(ctx, 8192)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	defer func() {
		if t.Failed() {
			r := w.Report(1)
			t.Logf("diagnostics: overruns=%d resubscribes=%d error=%q totals=%v counts=%+v",
				r.Overruns, r.Resubscribes, r.Error, r.Totals, r.Counts)
		}
	}()

	ipCmd(t, "link", "add", "nlst0", "type", "veth", "peer", "name", "nlst1")
	defer func() { _ = exec.Command("ip", "link", "del", "nlst0").Run() }()
	ipCmd(t, "addr", "add", "10.97.0.1/16", "dev", "nlst0")
	ipCmd(t, "link", "set", "nlst0", "up")
	ipCmd(t, "link", "set", "nlst1", "up")

	var batch strings.Builder
	// Under the snapshot's 4000-route cap, so the probe route below is not truncated.
	for i := range 2500 {
		fmt.Fprintf(&batch, "route add 10.%d.%d.0/24 dev nlst0\n", 100+i/256, i%256)
	}
	cmd := exec.Command("ip", "-batch", "-")
	cmd.Stdin = strings.NewReader(batch.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("route batch: %v: %s", err, out)
	}

	waitFor(t, "an overrun to be recorded", 60*time.Second, func() bool {
		return w.Report(1).Overruns >= 1
	})
	r := w.Report(1)
	if r.Resubscribes < 1 || r.Totals[models.NetlinkKindOverrun] < 1 {
		t.Fatalf("overrun not recorded as an event: %+v", r)
	}
	if !sawEvent(w, func(e models.NetlinkEvent) bool {
		return e.Kind == models.NetlinkKindOverrun && strings.Contains(e.Detail, "no buffer space")
	}) {
		t.Fatal("no overrun event naming ENOBUFS")
	}

	// Let the storm drain, then wait until the route subscription has been up
	// and unbroken for a moment. Losses during the storm are expected and each
	// one is a gap by design; a route added while the subscription is being
	// re-established would be lost, which is the recorder working as documented
	// and not what this test proves.
	slow.Store(false)
	lastResub := ^uint64(0)
	var stableSince time.Time
	waitFor(t, "the route subscription to settle after the storm", 60*time.Second, func() bool {
		rep := w.Report(1)
		if rep.Resubscribes != lastResub || strings.Contains(rep.Error, "route-subscribe") {
			lastResub, stableSince = rep.Resubscribes, time.Now()
			return false
		}
		return time.Since(stableSince) >= 2*time.Second
	})
	ipCmd(t, "route", "add", "10.96.0.0/24", "dev", "nlst0")
	waitFor(t, "a route added after the overrun to be recorded", 20*time.Second, func() bool {
		return sawEvent(w, func(e models.NetlinkEvent) bool {
			return e.Kind == "route" && e.Action == "new" && e.Destination == "10.96.0.0/24"
		})
	})
	// And the resync ran, so current state is healed.
	waitFor(t, "a snapshot resync after the loss", 30*time.Second, func() bool {
		s := w.Report(1).Snapshot
		if s == nil {
			return false
		}
		for _, rt := range s.Routes {
			if rt.Destination == "10.96.0.0/24" {
				return true
			}
		}
		return false
	})
}
