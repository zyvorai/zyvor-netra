// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/netlinkwatch"
	"github.com/zyvorai/netra/internal/rtnlactor"
)

// These load the real bpf/netra_rtnl.o (an fentry on rtnetlink_rcv_msg) and change
// the network from this very process and from a child `ip`, on a scratch veth, then
// require the records to name the requester correctly. The kernel decides who the
// requester is, so this is the only place that can be verified.

func rtnlObjectPath() string {
	if p := os.Getenv("NETRA_BPF_RTNL_TEST_OBJECT"); p != "" {
		return p
	}
	return "/tmp/netra_rtnl.o"
}

func startRTNL(t *testing.T) (*rtnlactor.Sensor, <-chan rtnlactor.Record) {
	t.Helper()
	s, err := rtnlactor.Load(rtnlactor.Options{ObjectPath: rtnlObjectPath()})
	if err != nil {
		t.Fatalf("load the rtnl actor sensor (kernel BTF and fentry needed): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan rtnlactor.Record, 8192)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, func(r rtnlactor.Record) {
			select {
			case ch <- r:
			default:
			}
		})
	}()
	t.Cleanup(func() { cancel(); <-done; _ = s.Close() })
	return s, ch
}

// next returns the first record matching pred within the timeout.
func next(t *testing.T, ch <-chan rtnlactor.Record, what string, pred func(rtnlactor.Record) bool) rtnlactor.Record {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-ch:
			if pred(r) {
				return r
			}
		case <-deadline:
			t.Fatalf("no record for: %s", what)
		}
	}
}

func selfComm(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestRTNLActorNamesTheProcessThatChangedTheNetwork(t *testing.T) {
	s, ch := startRTNL(t)
	me, comm := uint32(os.Getpid()), selfComm(t)

	_ = exec.Command("ip", "link", "del", "nlrt0").Run()
	run(t, "link", "add", "nlrt0", "type", "veth", "peer", "name", "nlrt1")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "nlrt0").Run() })
	run(t, "link", "set", "nlrt0", "up")
	link, err := netlink.LinkByName("nlrt0")
	if err != nil {
		t.Fatal(err)
	}

	// The child: `ip` made the veth and brought it up. Collect every request `ip` made
	// for a moment and check the set as a whole, logging each record so a failure shows
	// exactly what the kernel program reported.
	time.Sleep(500 * time.Millisecond)
	var seen []rtnlactor.Record
	for len(ch) > 0 {
		seen = append(seen, <-ch)
	}
	for _, r := range seen {
		if r.Comm == "ip" {
			t.Logf("ip request: %s flags=%#x ifindex=%d ifname=%q dest=%q tgid=%d", rtnlactor.TypeName(r.Type), r.Flags, r.IfIndex, r.IfName, r.Dest, r.TGID)
		}
	}
	var child, create, set *rtnlactor.Record
	for i := range seen {
		r := &seen[i]
		if r.Comm != "ip" || r.TGID == me {
			continue
		}
		if r.Type == rtnlactor.RTMNewLink && child == nil {
			child = r
		}
		if r.Type == rtnlactor.RTMNewLink && r.Flags&rtnlactor.NLMFCreate != 0 {
			create = r
		}
		// `ip link set` names its device by index (modern iproute2) or by IFLA_IFNAME. It
		// is preceded by iproute2's bare probe (no index, no name, 32 bytes), which names
		// nothing and is not this request.
		if r.Type == rtnlactor.RTMNewLink && r.Flags&rtnlactor.NLMFCreate == 0 && set == nil &&
			(r.IfIndex == uint32(link.Attrs().Index) || r.IfName == "nlrt0") {
			set = r
		}
	}
	if child == nil {
		t.Fatalf("no RTM_NEWLINK from the child ip among %d records", len(seen))
	}
	if child.CgroupID == 0 || child.PID == 0 {
		t.Fatalf("child record lacks ids: %+v", *child)
	}
	// The kernel program read the requester's network namespace (three CO-RE member
	// reads) and it is this one.
	if self := rtnlactor.SelfNetNS(); self == 0 || child.NetNS != self {
		t.Fatalf("the record's network namespace is %d, want this process's %d", child.NetNS, self)
	}
	// `ip link add nlrt0 ...` is a create naming the new device by IFLA_IFNAME.
	if create == nil || create.IfName != "nlrt0" {
		t.Fatalf("no create request carrying NLM_F_CREATE and the name nlrt0 (create=%+v)", create)
	}
	// `ip link set nlrt0 up` operates on an existing device: it names it by index or, as
	// modern iproute2 may, by IFLA_IFNAME with index 0. Either way the request must say which.
	if set == nil {
		t.Fatalf("no request on the existing link named it (ifindex %d or name nlrt0)", link.Attrs().Index)
	}
	// The probe must be reported as what it is: untargeted, and short.
	var probe *rtnlactor.Record
	for i := range seen {
		r := &seen[i]
		if r.Comm == "ip" && r.Type == rtnlactor.RTMNewLink && r.Flags&rtnlactor.NLMFCreate == 0 && r.IfIndex == 0 && r.IfName == "" {
			probe = r
			break
		}
	}
	if probe != nil && probe.Len != 32 {
		t.Fatalf("iproute2's untargeted probe should be the bare 32-byte message, got %+v", *probe)
	}

	// This process: an address, a route, and the route's removal, over our own netlink socket.
	_, dst, _ := net.ParseCIDR("10.93.0.0/24")
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.94.0.1"), Mask: net.CIDRMask(24, 32)}}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}
	mine := func(typ uint16) func(rtnlactor.Record) bool {
		return func(r rtnlactor.Record) bool { return r.Type == typ && r.TGID == me }
	}
	if r := next(t, ch, "RTM_NEWADDR from this process", mine(rtnlactor.RTMNewAddr)); r.Comm != comm {
		t.Fatalf("addr record comm=%q, want %q", r.Comm, comm)
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
		t.Fatal(err)
	}
	add := next(t, ch, "RTM_NEWROUTE from this process", mine(rtnlactor.RTMNewRoute))
	if add.Comm != comm || add.CgroupID == 0 || add.PID == 0 {
		t.Fatalf("route record=%+v, want comm %q with a cgroup", add, comm)
	}
	// A route request names its output interface (RTA_OIF) and its destination
	// (RTA_DST + prefix length): the kernel program must have read both.
	if add.IfIndex != uint32(link.Attrs().Index) || add.Dest != "10.93.0.0/24" {
		t.Fatalf("route record names ifindex %d dest %q, want %d and 10.93.0.0/24", add.IfIndex, add.Dest, link.Attrs().Index)
	}
	if age := time.Since(add.Wall); age < 0 || age > 30*time.Second {
		t.Fatalf("the wall time is off by %s: the monotonic-to-wall conversion is wrong", age)
	}
	if err := netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
		t.Fatal(err)
	}
	next(t, ch, "RTM_DELROUTE from this process", mine(rtnlactor.RTMDelRoute))

	// A read-only request (a route dump, RTM_GETROUTE) must not be recorded at all:
	// it is dropped in the kernel before anything is reserved.
	drain(ch)
	time.Sleep(300 * time.Millisecond)
	drain(ch)
	if _, err := netlink.RouteList(nil, netlink.FAMILY_ALL); err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkList(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	for {
		select {
		case r := <-ch:
			if r.TGID == me {
				t.Fatalf("a read-only request was recorded: %s from %q", rtnlactor.TypeName(r.Type), r.Comm)
			}
			continue
		default:
		}
		break
	}

	if dropped, err := s.Dropped(); err != nil || dropped != 0 {
		t.Fatalf("dropped=%d err=%v on a quiet ring buffer", dropped, err)
	}
}

func drain(ch <-chan rtnlactor.Record) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// The whole chain on a real kernel: the recorder hears a change, the sensor saw the
// request, and the joiner attributes one to the other. Includes the case the design
// exists for: a change nobody requested (the kernel taking a veth's carrier away when
// its peer is set down) must be reported as the kernel's, and must not be credited to
// the `ip link set <peer> down` that happened at the same moment.
func TestRTNLActorAttributesRecordedChanges(t *testing.T) {
	s, err := rtnlactor.Load(rtnlactor.Options{ObjectPath: rtnlObjectPath()})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	j := rtnlactor.NewJoiner(nil, rtnlactor.SelfNetNS())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var mu sync.Mutex
	var all []rtnlactor.Record
	go func() {
		defer close(done)
		s.Run(ctx, func(r rtnlactor.Record) {
			j.Add(r)
			mu.Lock()
			all = append(all, r)
			mu.Unlock()
		})
	}()
	// On failure, show every request the sensor saw from ip, so the join can be judged.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, r := range all {
			if r.Comm == "ip" {
				t.Logf("saw: %s at %s flags=%#x ifindex=%d ifname=%q dest=%q tgid=%d", rtnlactor.TypeName(r.Type), r.Wall.Format("15:04:05.000"), r.Flags, r.IfIndex, r.IfName, r.Dest, r.TGID)
			}
		}
	})
	t.Cleanup(func() { cancel(); <-done; _ = s.Close() })

	w, err := netlinkwatch.Start(ctx, 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	w.SetAttributor(j, 300*time.Millisecond)
	// The sensor must have been running for longer than the join window before a
	// change can honestly be called kernel-originated.
	time.Sleep(1200 * time.Millisecond)

	me, comm := uint32(os.Getpid()), selfComm(t)
	_ = exec.Command("ip", "link", "del", "nlat0").Run()
	run(t, "link", "add", "nlat0", "type", "veth", "peer", "name", "nlat1")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "nlat0").Run() })
	run(t, "link", "set", "nlat0", "up")
	run(t, "link", "set", "nlat1", "up")
	link, err := netlink.LinkByName("nlat0")
	if err != nil {
		t.Fatal(err)
	}

	// waitEvent polls the recorder's report until an event matching pred is attributed.
	waitEvent := func(what string, pred func(models.NetlinkEvent) bool) models.NetlinkEvent {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			for _, e := range w.Report(500).Events {
				if pred(e) {
					return e
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no attributed event for: %s", what)
		return models.NetlinkEvent{}
	}

	// A child process's route: ip.
	run(t, "route", "add", "10.91.0.0/24", "dev", "nlat0")
	e := waitEvent("route added by ip", func(e models.NetlinkEvent) bool {
		return e.Kind == "route" && e.Action == "new" && e.Destination == "10.91.0.0/24"
	})
	if e.Origin != models.NetlinkOriginProcess || e.Actor == nil || e.Actor.Comm != "ip" || e.Actor.PID == me || e.Actor.Confidence != models.NetlinkActorProbable {
		t.Fatalf("the route ip added was attributed as origin=%q actor=%+v", e.Origin, e.Actor)
	}

	// This process's own route.
	_, dst, _ := net.ParseCIDR("10.90.0.0/24")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
		t.Fatal(err)
	}
	e = waitEvent("route added by this process", func(e models.NetlinkEvent) bool {
		return e.Kind == "route" && e.Action == "new" && e.Destination == "10.90.0.0/24"
	})
	if e.Origin != models.NetlinkOriginProcess || e.Actor == nil || e.Actor.PID != me || e.Actor.Comm != comm {
		t.Fatalf("this process's route was attributed as origin=%q actor=%+v (want pid %d comm %q)", e.Origin, e.Actor, me, comm)
	}

	// ip link set nlat1 down: nlat1's own change was requested by ip; nlat0 then loses
	// its carrier, which nobody requested.
	//
	// Creating a veth makes udev workers (and anything else watching links) issue their
	// own requests on the new interfaces for a moment, so the join for events from that
	// period is legitimately ambiguous (a first run reported five requesters). Let those
	// age out of the join window, and look only at events after the command below, so
	// this asserts the one change it means to.
	time.Sleep(1500 * time.Millisecond)
	issued := time.Now()
	run(t, "link", "set", "nlat1", "down")
	admin := waitEvent("nlat1 set down by ip", func(e models.NetlinkEvent) bool {
		return e.Kind == "link" && e.Interface == "nlat1" && e.State != "up" && e.Origin != "" && e.ObservedAt.After(issued)
	})
	if admin.Origin != models.NetlinkOriginProcess || admin.Actor == nil || admin.Actor.Comm != "ip" {
		t.Fatalf("the admin's link down was attributed as origin=%q actor=%+v", admin.Origin, admin.Actor)
	}
	carrier := waitEvent("nlat0 carrier lost, requested by no one", func(e models.NetlinkEvent) bool {
		return e.Kind == "link" && e.Interface == "nlat0" && e.State != "up" && e.Origin != "" && e.ObservedAt.After(issued)
	})
	if carrier.Origin != models.NetlinkOriginKernel || carrier.Actor != nil {
		t.Logf("carrier event: %+v", carrier)
		t.Logf("admin event:   %+v", admin)
		t.Fatalf("a carrier loss nobody requested was attributed as origin=%q actor=%+v: it must be the kernel's, and not credited to `ip link set nlat1 down`", carrier.Origin, carrier.Actor)
	}

	if r := w.Report(500); r.Actor == nil || !r.Actor.Available || r.Actor.Records == 0 {
		t.Fatalf("the report must carry the sensor's status: %+v", r.Actor)
	}
}

// Interface indexes are per network namespace and the hook sees every namespace's
// requests (a pod's CNI setup included). Changes made in another namespace must not be
// recorded at all: the program is told which namespace to record and drops the rest.
func TestRTNLActorRecordsOnlyItsOwnNetworkNamespace(t *testing.T) {
	_, ch := startRTNL(t)
	self := rtnlactor.SelfNetNS()
	if self == 0 {
		t.Fatal("cannot read this process's network namespace")
	}

	_ = exec.Command("ip", "netns", "del", "nlxns").Run()
	run(t, "netns", "add", "nlxns")
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", "nlxns").Run() })
	_ = exec.Command("ip", "link", "del", "nlns0").Run()
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "nlns0").Run() })

	// A change in ANOTHER namespace (ip -n runs its request from inside it), then one in ours.
	run(t, "-n", "nlxns", "link", "add", "xa", "type", "veth", "peer", "name", "xb")
	run(t, "link", "add", "nlns0", "type", "veth", "peer", "name", "nlns1")

	mine := next(t, ch, "the create in this namespace", func(r rtnlactor.Record) bool {
		return r.Type == rtnlactor.RTMNewLink && r.Comm == "ip" && r.IfName == "nlns0"
	})
	if mine.NetNS != self {
		t.Fatalf("this namespace's request carries namespace %d, want %d", mine.NetNS, self)
	}
	// Give the other namespace's request every chance to appear, then look at everything seen.
	time.Sleep(500 * time.Millisecond)
	for len(ch) > 0 {
		r := <-ch
		if r.IfName == "xa" || r.IfName == "xb" {
			t.Fatalf("a request in another network namespace was recorded: %+v", r)
		}
		if r.NetNS != 0 && r.NetNS != self {
			t.Fatalf("a record from namespace %d reached a sensor recording %d: %+v", r.NetNS, self, r)
		}
	}
}
