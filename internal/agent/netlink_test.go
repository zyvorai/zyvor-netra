// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/netlinkwatch"
)

func newNetlinkWatchAgent() *Agent { return newListenQAgent() }

func TestNetlinkOffMeansNoReport(t *testing.T) {
	t.Setenv("NETRA_NETLINK", "off")
	a := newNetlinkWatchAgent()
	a.startNetlink(context.Background())
	rep, commit := a.readNetlink()
	if a.netlinkWatch != nil || rep != nil {
		t.Fatal("NETRA_NETLINK=off must produce no watcher and no report")
	}
	commit() // must be safe to call
}

func TestNetlinkUnavailableIsReportedNotHidden(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("the recorder starts on Linux; this covers platforms without RTNL")
	}
	t.Setenv("NETRA_NETLINK", "auto")
	a := newNetlinkWatchAgent()
	a.startNetlink(context.Background())
	rep, _ := a.readNetlink()
	if a.netlinkWatch != nil || rep == nil || rep.Unavailable == "" || rep.Available {
		t.Fatalf("a recorder that cannot start must say so, got %#v", rep)
	}
}

func TestNetlinkStartsAndReportsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs a Linux RTNL socket")
	}
	t.Setenv("NETRA_NETLINK", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newNetlinkWatchAgent()
	a.startNetlink(ctx)
	if a.netlinkWatch == nil {
		t.Fatal("an unset NETRA_NETLINK must behave as auto (on)")
	}
	defer a.netlinkWatch.Close()
	rep, commit := a.readNetlink()
	if rep == nil || !rep.Available || rep.Epoch == 0 {
		t.Fatalf("report=%#v", rep)
	}
	if rep.Snapshot == nil || rep.Counts.Links == 0 {
		t.Fatalf("the first report must carry the full snapshot: %#v", rep)
	}
	commit()
	again, _ := a.readNetlink()
	if again.Snapshot != nil {
		t.Fatal("an unchanged, delivered snapshot must not be re-shipped every tick")
	}
}

func TestNetlinkEventBufferEnv(t *testing.T) {
	t.Setenv("NETRA_NETLINK_EVENT_BUFFER", "2048")
	if got := netlinkEventBuffer(); got != 2048 {
		t.Fatalf("got %d", got)
	}
	for _, v := range []string{"", "0", "-1", "no", "1.5"} {
		t.Setenv("NETRA_NETLINK_EVENT_BUFFER", v)
		if got := netlinkEventBuffer(); got != netlinkwatch.DefaultCapacity {
			t.Fatalf("value %q got %d, want the default", v, got)
		}
	}
}

type fakeActorTarget struct {
	attributor netlinkwatch.Attributor
	grace      time.Duration
	why        string
}

func (f *fakeActorTarget) SetAttributor(a netlinkwatch.Attributor, g time.Duration) {
	f.attributor, f.grace = a, g
}
func (f *fakeActorTarget) SetActorUnavailable(why string) { f.why = why }

func TestRTNLActorOffLeavesTheRecorderAlone(t *testing.T) {
	t.Setenv("NETRA_RTNL_ACTOR", "off")
	a := newNetlinkWatchAgent()
	f := &fakeActorTarget{}
	a.startRTNLActor(context.Background(), f)
	if f.attributor != nil || f.why != "" || a.rtnlSensor != nil {
		t.Fatalf("NETRA_RTNL_ACTOR=off must change nothing: %+v", f)
	}
}

func TestRTNLActorThatCannotLoadIsReportedWithItsReasonAndDoesNotStopAnything(t *testing.T) {
	t.Setenv("NETRA_RTNL_ACTOR", "auto")
	t.Setenv("NETRA_BPF_RTNL_OBJECT", "/nonexistent/netra_rtnl.o")
	a := newNetlinkWatchAgent()
	f := &fakeActorTarget{}
	a.startRTNLActor(context.Background(), f)
	if f.attributor != nil || a.rtnlSensor != nil {
		t.Fatal("a sensor that failed to load must not attach anything")
	}
	if f.why == "" || len(f.why) > maxWhy {
		t.Fatalf("the report must carry a bounded reason, got %q", f.why)
	}
}

func TestRTNLResolveNamesThePodOfACgroup(t *testing.T) {
	a := newNetlinkWatchAgent()
	a.workloadByCgroup = map[uint64]models.WorkloadIdentity{
		77: {Namespace: "kube-system", Pod: "calico-node-x", WorkloadName: "calico-node"},
	}
	ns, pod, wl, ok := a.rtnlResolve(77)
	if !ok || ns != "kube-system" || pod != "calico-node-x" || wl != "calico-node" {
		t.Fatalf("resolve=%q %q %q %v", ns, pod, wl, ok)
	}
	if _, _, _, ok := a.rtnlResolve(1); ok {
		t.Fatal("a host cgroup has no pod")
	}
}
