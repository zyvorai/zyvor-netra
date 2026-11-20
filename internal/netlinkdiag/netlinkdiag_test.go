// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package netlinkdiag

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var t0 = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func agent(node string, snap *models.NetlinkSnapshot, ev ...models.NetlinkEvent) models.AgentStatus {
	for i := range ev {
		ev[i].Sequence = uint64(i + 1)
		ev[i].Epoch = 1
	}
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, Netlink: &models.NetlinkReport{Available: true, Epoch: 1, Snapshot: snap, Events: ev}}}
}

func snapAt(sec int, s models.NetlinkSnapshot) *models.NetlinkSnapshot {
	s.ResyncedAt = at(sec)
	return &s
}

func defRoute(action, fam, gw, iface string, idx, sec int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: "route", Action: action, Family: fam, Destination: "default", Gateway: gw,
		Interface: iface, InterfaceIndex: idx, Table: 254, ObservedAt: at(sec)}
}

func link(action, typ, name string, idx int, state string, mtu, sec int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: "link", Action: action, LinkType: typ, Interface: name, InterfaceIndex: idx,
		State: state, MTU: mtu, ObservedAt: at(sec)}
}

func neigh(action, addr, state string, idx, sec int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: "neighbor", Action: action, Address: addr, MAC: "02:00:00:aa:bb:cc",
		State: state, InterfaceIndex: idx, ObservedAt: at(sec)}
}

func build(now int, a ...models.AgentStatus) models.NetlinkFindingsResponse {
	return Build(a, at(now), DefaultWindow)
}

func kinds(r models.NetlinkFindingsResponse) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Severity+":"+f.Kind)
	}
	return out
}

func only(t *testing.T, r models.NetlinkFindingsResponse, want string) models.NetlinkFinding {
	t.Helper()
	if len(r.Findings) != 1 || r.Findings[0].Severity+":"+r.Findings[0].Kind != want {
		t.Fatalf("findings=%v, want exactly %s", kinds(r), want)
	}
	return r.Findings[0]
}

func none(t *testing.T, r models.NetlinkFindingsResponse) {
	t.Helper()
	if len(r.Findings) != 0 {
		t.Fatalf("expected no findings, got %v", kinds(r))
	}
}

func TestDefaultRouteRemovedIsCriticalAndNamesTheOldNextHop(t *testing.T) {
	a := agent("n1", nil, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10))
	f := only(t, build(60, a), "critical:"+KindDefaultRouteRemoved)
	if !strings.Contains(f.Message, "IPv4") || !strings.Contains(f.Message, "10.0.0.1") || !strings.Contains(f.Message, "eth0") {
		t.Fatalf("message=%q", f.Message)
	}
	if f.Subject != "n1" || len(f.Evidence) != 1 || f.FirstObserved != at(10) {
		t.Fatalf("finding=%+v", f)
	}
}

func TestDefaultRouteReplacedOrReaddedIsNotAFinding(t *testing.T) {
	replaced := agent("n1", nil, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10), defRoute("new", "ipv4", "10.0.0.2", "eth0", 2, 10))
	none(t, build(120, replaced))
}

func TestDefaultRouteStillPresentInAFreshSnapshotIsNotAFinding(t *testing.T) {
	snap := snapAt(50, models.NetlinkSnapshot{Routes: []models.NetlinkRoute{{Family: "ipv4", Destination: "default", Table: 254, Gateway: "10.0.0.2", Type: 1}}})
	none(t, build(60, agent("n1", snap, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10))))
	// A blackhole default is not a working one.
	bh := snapAt(50, models.NetlinkSnapshot{Routes: []models.NetlinkRoute{{Family: "ipv4", Destination: "default", Table: 254, Type: 6}}})
	only(t, build(60, agent("n1", bh, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10))), "critical:"+KindDefaultRouteRemoved)
}

func TestDefaultRouteSnapshotOlderThanTheDeleteDoesNotHideIt(t *testing.T) {
	old := snapAt(5, models.NetlinkSnapshot{Routes: []models.NetlinkRoute{{Family: "ipv4", Destination: "default", Table: 254, Type: 1}}})
	only(t, build(20, agent("n1", old, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10))), "critical:"+KindDefaultRouteRemoved)
}

func TestIPv6DefaultIsWarningAndOtherTablesAreIgnored(t *testing.T) {
	r := build(60, agent("n1", nil, defRoute("delete", "ipv6", "fe80::1", "eth0", 2, 10)))
	only(t, r, "warning:"+KindDefaultRouteRemoved)
	other := defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10)
	other.Table = 100 // a policy-routing table, not main
	none(t, build(60, agent("n1", nil, other)))
}

func TestOldChangesAndUnreadNodesProduceNothingAndAreCounted(t *testing.T) {
	old := agent("n1", nil, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10))
	r := Build([]models.AgentStatus{old}, at(10+int((DefaultWindow+time.Minute).Seconds())), DefaultWindow)
	none(t, r)
	stale := agent("stale", nil, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10))
	stale.Stale = true
	off := models.AgentStatus{AgentReport: models.AgentReport{Node: "off"}}
	blind := models.AgentStatus{AgentReport: models.AgentReport{Node: "blind", Netlink: &models.NetlinkReport{Unavailable: "no rtnl"}}}
	r = build(60, stale, off, blind, agent("ok", nil))
	none(t, r)
	if r.Evaluated != 1 || r.Skipped != 3 {
		t.Fatalf("evaluated=%d skipped=%d, want 1 and 3: silence must not read as health", r.Evaluated, r.Skipped)
	}
}

func TestGatewayNeighborFailureIsCriticalAndOthersAreGraded(t *testing.T) {
	routes := []models.NetlinkRoute{{Family: "ipv4", Destination: "default", Table: 254, Gateway: "10.0.0.1", Type: 1}}
	snap := snapAt(100, models.NetlinkSnapshot{Routes: routes, Neighbors: []models.NetlinkNeighbor{
		{InterfaceIndex: 2, Address: "10.0.0.1", State: "failed"},
		{InterfaceIndex: 2, Address: "10.0.0.9", State: "failed"},
	}})
	a := agent("n1", snap, neigh("new", "10.0.0.1", "failed", 2, 50), neigh("new", "10.0.0.9", "failed", 2, 51))
	r := build(120, a)
	if got := kinds(r); len(got) != 2 || got[0] != "critical:"+KindGatewayUnreachable || got[1] != "info:"+KindNeighborFailed {
		t.Fatalf("findings=%v", got)
	}
	if strings.Contains(r.Findings[0].Message+r.Findings[1].Message, "02:00") {
		t.Fatal("a MAC address leaked into a finding message")
	}
	if len(r.Findings[0].Evidence) == 0 || r.Findings[0].Evidence[0].MAC == "" {
		t.Fatal("evidence should keep the MAC for the authenticated API")
	}
}

func TestSeveralFailedNeighborsAreAWarningAndTheListIsBounded(t *testing.T) {
	var ev []models.NetlinkEvent
	var ns []models.NetlinkNeighbor
	for i, addr := range []string{"10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5"} {
		ev = append(ev, neigh("new", addr, "failed", 2, 10+i))
		ns = append(ns, models.NetlinkNeighbor{InterfaceIndex: 2, Address: addr, State: "failed"})
	}
	f := only(t, build(120, agent("n1", snapAt(100, models.NetlinkSnapshot{Neighbors: ns}), ev...)), "warning:"+KindNeighborFailed)
	if !strings.Contains(f.Message, "5 neighbor") || !strings.Contains(f.Message, "and 2 more") || f.Value != 5 {
		t.Fatalf("message=%q value=%v", f.Message, f.Value)
	}
}

func TestNeighborThatRecoveredOrDiedOrIsIncompleteIsNotAFinding(t *testing.T) {
	recovered := snapAt(100, models.NetlinkSnapshot{Neighbors: []models.NetlinkNeighbor{{InterfaceIndex: 2, Address: "10.0.0.9", State: "reachable"}}})
	none(t, build(120, agent("n1", recovered, neigh("new", "10.0.0.9", "failed", 2, 50))))
	none(t, build(120, agent("n1", nil, neigh("new", "10.0.0.9", "failed", 2, 50), neigh("delete", "10.0.0.9", "failed", 2, 60))))
	// INCOMPLETE is ARP in flight, the normal state of every new peer.
	none(t, build(120, agent("n1", nil, neigh("new", "10.0.0.9", "incomplete", 2, 50))))
}

func TestFreshNeighborFailureWaitsForASnapshotThenReportsOnTheEvent(t *testing.T) {
	a := agent("n1", nil, neigh("new", "10.0.0.9", "failed", 2, 100))
	none(t, build(110, a)) // 10 s old, no snapshot yet: wait
	// Past the confirmation window with still no snapshot: report on the event.
	only(t, build(100+int(confirmWithin.Seconds())+1, a), "info:"+KindNeighborFailed)
}

func TestHostLinkDownIsWarningAndCriticalWhenItCarriedTheDefaultRoute(t *testing.T) {
	down := link("new", "device", "eth1", 3, "down", 1500, 10)
	snapDown := snapAt(100, models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 3, Name: "eth1", State: "down"}}})
	f := only(t, build(120, agent("n1", snapDown, down)), "warning:"+KindLinkDown)
	if !strings.Contains(f.Message, "eth1 (down)") {
		t.Fatalf("message=%q", f.Message)
	}
	// The kernel drops a link's routes as it goes down, so the removed default
	// route is what shows the link carried it.
	carrier := agent("n1", snapDown, defRoute("delete", "ipv4", "10.0.0.1", "eth1", 3, 10), down)
	got := kinds(build(120, carrier))
	if len(got) != 2 || got[0] != "critical:"+KindDefaultRouteRemoved || got[1] != "critical:"+KindLinkDown {
		t.Fatalf("findings=%v", got)
	}
}

func TestLowerLayerDownIsRecognised(t *testing.T) {
	// The netlink library says "lower-layer-down"; matching "lowerlayerdown" was
	// the bug that made the first design's link check dead code.
	snap := snapAt(100, models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 4, Name: "bond0.100", State: "lower-layer-down"}}})
	only(t, build(120, agent("n1", snap, link("new", "vlan", "bond0.100", 4, "lower-layer-down", 1500, 10))), "warning:"+KindLinkDown)
}

func TestPodVethsBridgesAndTunnelsNeverAlert(t *testing.T) {
	snap := snapAt(100, models.NetlinkSnapshot{})
	a := agent("n1", snap,
		link("new", "veth", "lxc1234", 10, "down", 1500, 10),
		link("delete", "veth", "lxc1234", 10, "down", 1500, 20),
		link("new", "bridge", "virbr0", 11, "down", 1500, 30),
		link("new", "vxlan", "cilium_vxlan", 12, "down", 1500, 40),
	)
	none(t, build(120, a))
}

func TestLinkThatCameBackUpIsNotAFinding(t *testing.T) {
	flap := agent("n1", nil, link("new", "device", "eth1", 3, "down", 1500, 10), link("new", "device", "eth1", 3, "up", 1500, 20))
	none(t, build(120, flap))
	snapUp := snapAt(100, models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 3, Name: "eth1", State: "up"}}})
	none(t, build(120, agent("n1", snapUp, link("new", "device", "eth1", 3, "down", 1500, 10))))
}

func TestHostLinkDeletedIsAFindingUnlessItReturned(t *testing.T) {
	del := link("delete", "bond", "bond0", 5, "down", 1500, 10)
	gone := snapAt(100, models.NetlinkSnapshot{})
	only(t, build(120, agent("n1", gone, del)), "warning:"+KindLinkDeleted)
	back := snapAt(100, models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 9, Name: "bond0", State: "up"}}})
	none(t, build(120, agent("n1", back, del)))
}

func TestMTUChangeNeedsAPreviousValueAndNetsOutAFlap(t *testing.T) {
	before := link("new", "device", "eth0", 2, "up", 1500, -3600)
	f := only(t, build(120, agent("n1", nil, before, link("new", "device", "eth0", 2, "up", 1400, 10))), "warning:"+KindMTUChanged)
	if !strings.Contains(f.Message, "eth0 1500 to 1400") {
		t.Fatalf("message=%q", f.Message)
	}
	// First sighting is not a change.
	none(t, build(120, agent("n1", nil, link("new", "device", "eth0", 2, "up", 1400, 10))))
	// 1500 -> 9000 -> 1500 inside the window ends where it started.
	none(t, build(120, agent("n1", nil, before, link("new", "device", "eth0", 2, "up", 9000, 10), link("new", "device", "eth0", 2, "up", 1500, 20))))
	// A pod veth's MTU is not an uplink's.
	none(t, build(120, agent("n1", nil, link("new", "veth", "lxc1", 9, "up", 1500, -3600), link("new", "veth", "lxc1", 9, "up", 1450, 10))))
}

func TestRecorderOverrunsAreReportedSoQuietIsNotTrustedBlindly(t *testing.T) {
	enobufs := models.NetlinkEvent{Kind: "overrun", Action: "lost", Detail: "route: Receive failed: no buffer space available", ObservedAt: at(10)}
	f := only(t, build(120, agent("n1", nil, enobufs)), "warning:"+KindOverrun)
	if !strings.Contains(f.Message, "1 time") || !strings.Contains(f.Message, "1 receive-buffer") {
		t.Fatalf("message=%q", f.Message)
	}
	other := models.NetlinkEvent{Kind: "overrun", Action: "lost", Detail: "link: connection reset", ObservedAt: at(10)}
	only(t, build(120, agent("n1", nil, other)), "info:"+KindOverrun)
}

func TestFindingsAreSortedAndAnomaliesCarryNoMAC(t *testing.T) {
	a := agent("b", nil, defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10))
	b := agent("a", nil, models.NetlinkEvent{Kind: "overrun", Action: "lost", Detail: "x: connection reset", ObservedAt: at(10)})
	c := agent("c", snapAt(100, models.NetlinkSnapshot{Neighbors: []models.NetlinkNeighbor{{InterfaceIndex: 2, Address: "10.0.0.9", State: "failed"}}}), neigh("new", "10.0.0.9", "failed", 2, 10))
	r := build(120, a, b, c)
	got := kinds(r)
	// Severity first, then node name: node "a"'s overrun precedes node "c"'s neighbor finding.
	want := []string{"critical:" + KindDefaultRouteRemoved, "info:" + KindOverrun, "info:" + KindNeighborFailed}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("order=%v, want %v", got, want)
	}
	for _, an := range Anomalies(r.Findings) {
		if an.SourceKey != "node:"+an.Subject || strings.Contains(an.Message, "02:00") {
			t.Fatalf("anomaly=%+v", an)
		}
		switch an.Severity {
		case "critical", "warning", "info":
		default:
			t.Fatalf("severity %q would fail closed in the notify filters", an.Severity)
		}
	}
}

func TestZeroWindowFallsBackToTheDefault(t *testing.T) {
	r := Build(nil, at(0), 0)
	if r.Window != DefaultWindow.String() || r.Findings == nil {
		t.Fatalf("window=%q findings=%v", r.Window, r.Findings)
	}
}

func withActor(e models.NetlinkEvent, origin string, a *models.NetlinkActor) models.NetlinkEvent {
	e.Origin, e.Actor = origin, a
	return e
}

func TestFindingsNameWhoAskedForTheChangeOnlyWhenTheSensorCouldTell(t *testing.T) {
	probable := &models.NetlinkActor{Confidence: "probable", Comm: "calico-node", PID: 42, Namespace: "kube-system", Pod: "calico-node-x"}
	del := withActor(defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10), models.NetlinkOriginProcess, probable)
	f := only(t, build(60, agent("n1", nil, del)), "critical:"+KindDefaultRouteRemoved)
	for _, want := range []string{"by calico-node (pid 42, pod kube-system/calico-node-x)", "10.0.0.1", "eth0", "none remains"} {
		if !strings.Contains(f.Message, want) {
			t.Fatalf("message %q lacks %q", f.Message, want)
		}
	}

	// Nobody requested it: a route dropped as a link went down.
	kernel := withActor(defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10), models.NetlinkOriginKernel, nil)
	f = only(t, build(60, agent("n1", nil, kernel)), "critical:"+KindDefaultRouteRemoved)
	if !strings.Contains(f.Message, "by the kernel (no process requested it)") {
		t.Fatalf("message=%q", f.Message)
	}

	// Two requesters at once: listed, never picked between.
	amb := withActor(defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10), models.NetlinkOriginProcess,
		&models.NetlinkActor{Confidence: "ambiguous", Candidates: 2, Alternatives: []string{"ip", "kubelet"}})
	f = only(t, build(60, agent("n1", nil, amb)), "critical:"+KindDefaultRouteRemoved)
	if !strings.Contains(f.Message, "by one of ip, kubelet (ambiguous: 2 requesters") || strings.Contains(f.Message, "pid") {
		t.Fatalf("message=%q", f.Message)
	}

	// The sensor could not tell (off, or dropped requests): the message claims nothing.
	unknown := defRoute("delete", "ipv4", "10.0.0.1", "eth0", 2, 10)
	f = only(t, build(60, agent("n1", nil, unknown)), "critical:"+KindDefaultRouteRemoved)
	if strings.Contains(f.Message, " by ") {
		t.Fatalf("a message without attribution must not name anyone: %q", f.Message)
	}
}

func TestALinkThatWentDownSaysWhetherAProcessOrTheKernelDidIt(t *testing.T) {
	snap := snapAt(100, models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 3, Name: "eth1", State: "down"}}})
	carrier := withActor(link("new", "device", "eth1", 3, "down", 1500, 10), models.NetlinkOriginKernel, nil)
	f := only(t, build(120, agent("n1", snap, carrier)), "warning:"+KindLinkDown)
	if !strings.Contains(f.Message, "eth1 (down) by the kernel") {
		t.Fatalf("a carrier loss must read as the kernel's doing: %q", f.Message)
	}
	admin := withActor(link("new", "device", "eth1", 3, "down", 1500, 10), models.NetlinkOriginProcess,
		&models.NetlinkActor{Confidence: "probable", Comm: "ip", PID: 900})
	f = only(t, build(120, agent("n1", snap, admin)), "warning:"+KindLinkDown)
	if !strings.Contains(f.Message, "eth1 (down) by ip (pid 900)") {
		t.Fatalf("an administrator's ip link set down must name ip: %q", f.Message)
	}
}

func TestAMixOfRequestersIsNotSummarisedAsOne(t *testing.T) {
	snap := snapAt(100, models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 3, Name: "eth1", State: "down"}, {Index: 4, Name: "eth2", State: "down"}}})
	a := withActor(link("new", "device", "eth1", 3, "down", 1500, 10), models.NetlinkOriginKernel, nil)
	b := withActor(link("new", "device", "eth2", 4, "down", 1500, 11), models.NetlinkOriginProcess, &models.NetlinkActor{Confidence: "probable", Comm: "ip", PID: 1})
	f := only(t, build(120, agent("n1", snap, a, b)), "warning:"+KindLinkDown)
	if strings.Contains(f.Message, " by ") {
		t.Fatalf("two links with different requesters must not be attributed in one breath: %q", f.Message)
	}
}
