// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package rtnlactor

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var t0 = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

// joiner starts long before the changes under test, so "the sensor just started"
// never masks what a test is about.
func joiner() *Joiner { return newJoiner(nil, t0.Add(-time.Hour)) }

func rec(tgid uint32, comm string, typ uint16, ifindex uint32, ms int) Record {
	return Record{TGID: tgid, PID: tgid, Comm: comm, Type: typ, IfIndex: ifindex, CgroupID: 100 + uint64(tgid), Wall: at(ms)}
}

func route(action string, ms int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: models.NetlinkKindRoute, Action: action, ObservedAt: at(ms), Destination: "10.9.0.0/24"}
}

func onLink(kind, action string, idx, ms int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: kind, Action: action, InterfaceIndex: idx, ObservedAt: at(ms)}
}

func TestOneRequesterIsAProbableActorWithItsPod(t *testing.T) {
	j := newJoiner(func(cg uint64) (string, string, string, bool) {
		if cg == 100+42 {
			return "kube-system", "calico-node-x", "calico-node", true
		}
		return "", "", "", false
	}, t0.Add(-time.Hour))
	j.Add(rec(42, "calico-node", RTMDelRoute, 0, 1000))
	a, origin := j.Attribute(route("delete", 1030))
	if origin != models.NetlinkOriginProcess || a == nil || a.Confidence != models.NetlinkActorProbable {
		t.Fatalf("actor=%+v origin=%q", a, origin)
	}
	if a.Comm != "calico-node" || a.PID != 42 || a.Namespace != "kube-system" || a.Pod != "calico-node-x" || a.Workload != "calico-node" {
		t.Fatalf("actor=%+v", a)
	}
	// A host process has no pod.
	j.Add(rec(7, "ip", RTMNewRoute, 0, 5000))
	a, _ = j.Attribute(route("new", 5020))
	if a.Comm != "ip" || a.Pod != "" || a.Namespace != "" {
		t.Fatalf("host process: %+v", a)
	}
}

func TestTheRequestTypeMustMatchTheChange(t *testing.T) {
	j := joiner()
	j.Add(rec(1, "ip", RTMNewRoute, 0, 1000))
	// A route was DELETED; an add request does not explain it.
	if a, origin := j.Attribute(route("delete", 1020)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("a mismatched type was attributed: %+v %q", a, origin)
	}
	// A link "new" is explained by NEWLINK or SETLINK.
	j.Add(rec(2, "ip", RTMSetLink, 5, 2000))
	if a, _ := j.Attribute(onLink(models.NetlinkKindLink, "new", 5, 2020)); a == nil || a.Comm != "ip" {
		t.Fatalf("SETLINK must explain a link change: %+v", a)
	}
	j.Add(rec(3, "ip", RTMDelLink, 6, 3000))
	if a, _ := j.Attribute(onLink(models.NetlinkKindLink, "delete", 6, 3020)); a == nil {
		t.Fatal("DELLINK must explain a link deletion")
	}
	if a, origin := j.Attribute(onLink(models.NetlinkKindLink, "new", 6, 3020)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("a deletion request must not explain a link that appeared: %+v %q", a, origin)
	}
}

func TestTheTimeWindowHasEdges(t *testing.T) {
	cases := []struct {
		name    string
		reqAt   int
		matches bool
	}{
		{"request 700 ms before the notification", 300, true},
		{"request 800 ms before: too old", 200, false},
		{"request 50 ms after (read before the record)", 1050, true},
		{"request 200 ms after: too late", 1200, false},
	}
	for _, c := range cases {
		j := joiner()
		j.Add(rec(1, "ip", RTMNewRoute, 0, c.reqAt))
		a, origin := j.Attribute(route("new", 1000))
		if (a != nil) != c.matches {
			t.Errorf("%s: matched=%v origin=%q", c.name, a != nil, origin)
		}
	}
}

func TestARequestForAnotherInterfaceDoesNotExplainThisOne(t *testing.T) {
	j := joiner()
	// ip link set <peer> down: the kernel then takes the far end's carrier away.
	j.Add(rec(1, "ip", RTMSetLink, 7, 1000))
	if a, origin := j.Attribute(onLink(models.NetlinkKindLink, "new", 5, 1020)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("the carrier loss on ifindex 5 was credited to a request for ifindex 7: %+v %q", a, origin)
	}
	if a, _ := j.Attribute(onLink(models.NetlinkKindLink, "new", 7, 1020)); a == nil {
		t.Fatal("the request for ifindex 7 must explain the change on ifindex 7")
	}
	// A link create names no interface (ifindex 0), so it explains any.
	j2 := joiner()
	j2.Add(linkRec(2, "ip", RTMNewLink, 0, "nlat0", NLMFCreate|0x1|0x200, 1000)) // ip link add ... (NLM_F_CREATE)
	if a, _ := j2.Attribute(onLink(models.NetlinkKindLink, "new", 9, 1020)); a == nil {
		t.Fatal("a create request (no ifindex) must match")
	}
	// An event with no interface index cannot be ruled out either.
	j3 := joiner()
	j3.Add(rec(3, "ip", RTMSetLink, 7, 1000))
	if a, _ := j3.Attribute(onLink(models.NetlinkKindLink, "new", 0, 1020)); a == nil {
		t.Fatal("an event without an ifindex must not be ruled out by the interface check")
	}
}

func TestABatchFromOneProcessIsOneActor(t *testing.T) {
	j := joiner()
	for i := 0; i < 500; i++ {
		j.Add(rec(9, "ip", RTMNewRoute, 0, 1000+i%50))
	}
	a, _ := j.Attribute(route("new", 1040))
	if a == nil || a.Confidence != models.NetlinkActorProbable || a.Candidates != 1 {
		t.Fatalf("a batch from one process must be one probable actor: %+v", a)
	}
}

func TestSeveralRequestersAreAmbiguousAndNoneIsNamed(t *testing.T) {
	j := joiner()
	j.Add(rec(1, "kubelet", RTMNewRoute, 0, 1000))
	j.Add(rec(2, "calico-node", RTMNewRoute, 0, 1010))
	j.Add(rec(3, "calico-node", RTMNewRoute, 0, 1020)) // a second process with the same name
	a, origin := j.Attribute(route("new", 1030))
	if origin != models.NetlinkOriginProcess || a == nil || a.Confidence != models.NetlinkActorAmbiguous || a.Candidates != 3 {
		t.Fatalf("actor=%+v origin=%q", a, origin)
	}
	if a.Comm != "" || a.PID != 0 || a.Pod != "" {
		t.Fatalf("an ambiguous match must not name a process: %+v", a)
	}
	if len(a.Alternatives) != 2 || a.Alternatives[0] != "calico-node" || a.Alternatives[1] != "kubelet" {
		t.Fatalf("alternatives=%v", a.Alternatives)
	}
	// The list is bounded.
	j2 := joiner()
	for i, c := range []string{"a", "b", "c", "d", "e"} {
		j2.Add(rec(uint32(i+1), c, RTMNewRoute, 0, 1000))
	}
	a, _ = j2.Attribute(route("new", 1010))
	if a.Candidates != 5 || len(a.Alternatives) != 3 {
		t.Fatalf("candidates=%d alternatives=%v", a.Candidates, a.Alternatives)
	}
}

func TestKernelOriginIsOnlyClaimedWhenTheSensorCouldHaveSeenARequest(t *testing.T) {
	// The sensor started 200 ms before the change: a request from before that would not be in the ring.
	fresh := newJoiner(nil, at(800))
	if a, origin := fresh.Attribute(route("new", 1000)); a != nil || origin != "" {
		t.Fatalf("claimed kernel origin 200 ms after start: %q", origin)
	}
	// A drop near the change: the missing request may be the dropped one.
	dropped := joiner()
	dropped.NoteDropped(3, at(500))
	if _, origin := dropped.Attribute(route("new", 1000)); origin != "" {
		t.Fatalf("claimed kernel origin next to a ring-buffer drop: %q", origin)
	}
	// The same drop long ago no longer matters.
	if _, origin := dropped.Attribute(route("new", 60_000)); origin != models.NetlinkOriginKernel {
		t.Fatalf("a drop a minute ago must not block the claim: %q", origin)
	}
	// Drop counter unchanged is not a new drop.
	dropped.NoteDropped(3, at(59_000))
	if _, origin := dropped.Attribute(route("new", 60_000)); origin != models.NetlinkOriginKernel {
		t.Fatalf("an unchanged drop counter was treated as a fresh drop: %q", origin)
	}
	// The ring wrapped: its oldest request is newer than the window, so a match could have been evicted.
	wrapped := joiner()
	for i := 0; i < maxRecords+10; i++ {
		wrapped.Add(rec(uint32(i+1), "x", RTMNewNeigh, 0, 2000)) // all at 2 s
	}
	if _, origin := wrapped.Attribute(route("new", 2100)); origin != "" {
		t.Fatalf("claimed kernel origin with a ring that no longer reaches back: %q", origin)
	}
}

func TestChangesNoRequestCanExplainAreLeftAlone(t *testing.T) {
	j := joiner()
	if a, origin := j.Attribute(models.NetlinkEvent{Kind: models.NetlinkKindOverrun, Action: "lost", ObservedAt: at(1000)}); a != nil || origin != "" {
		t.Fatalf("the recorder's own overrun is not a network change: %+v %q", a, origin)
	}
	if a, origin := j.Attribute(models.NetlinkEvent{Kind: models.NetlinkKindRoute, Action: "new"}); a != nil || origin != "" {
		t.Fatalf("an event with no time cannot be joined: %+v %q", a, origin)
	}
}

func TestStatusCountsRecordsAndDrops(t *testing.T) {
	j := joiner()
	j.Add(rec(1, "ip", RTMNewRoute, 0, 1))
	j.Add(rec(1, "ip", RTMNewRoute, 0, 2))
	j.NoteDropped(4, at(3))
	s := j.Status()
	if !s.Available || s.Records != 2 || s.Dropped != 4 {
		t.Fatalf("status=%+v", s)
	}
}

func routeRec(tgid uint32, comm string, typ uint16, ifindex uint32, dest string, ms int) Record {
	r := rec(tgid, comm, typ, ifindex, ms)
	r.Dest = dest
	return r
}

func routeTo(action, dst string, ifindex, ms int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: models.NetlinkKindRoute, Action: action, Destination: dst, InterfaceIndex: ifindex, ObservedAt: at(ms)}
}

// The case that failed on a real kernel: two processes add a route on the SAME
// interface in the same instant. Neither interface nor time separates them; the
// destination does.
func TestTwoProcessesAddingRoutesOnOneInterfaceAreToldApartByDestination(t *testing.T) {
	j := joiner()
	j.Add(routeRec(11, "ip", RTMNewRoute, 4, "10.91.0.0/24", 1000))
	j.Add(routeRec(22, "calico-node", RTMNewRoute, 4, "10.90.0.0/24", 1100))

	a, origin := j.Attribute(routeTo("new", "10.91.0.0/24", 4, 1150))
	if origin != models.NetlinkOriginProcess || a == nil || a.Comm != "ip" || a.Confidence != models.NetlinkActorProbable {
		t.Fatalf("10.91.0.0/24 must be ip's: %+v %q", a, origin)
	}
	a, _ = j.Attribute(routeTo("new", "10.90.0.0/24", 4, 1150))
	if a == nil || a.Comm != "calico-node" || a.Confidence != models.NetlinkActorProbable {
		t.Fatalf("10.90.0.0/24 must be calico-node's: %+v", a)
	}
}

func TestTheSameRouteFromTwoProcessesIsStillAmbiguous(t *testing.T) {
	j := joiner()
	j.Add(routeRec(11, "ip", RTMNewRoute, 4, "10.91.0.0/24", 1000))
	j.Add(routeRec(22, "calico-node", RTMNewRoute, 4, "10.91.0.0/24", 1050))
	a, _ := j.Attribute(routeTo("new", "10.91.0.0/24", 4, 1100))
	if a == nil || a.Confidence != models.NetlinkActorAmbiguous || a.Candidates != 2 {
		t.Fatalf("two requests for the very same prefix cannot be told apart: %+v", a)
	}
}

func TestARouteRequestForAnotherInterfaceOrPrefixDoesNotExplainThisOne(t *testing.T) {
	j := joiner()
	j.Add(routeRec(1, "ip", RTMNewRoute, 4, "10.91.0.0/24", 1000))
	if a, origin := j.Attribute(routeTo("new", "10.91.0.0/24", 9, 1050)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("a route on another interface was credited: %+v %q", a, origin)
	}
	if a, origin := j.Attribute(routeTo("new", "10.99.0.0/24", 4, 1050)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("a route to another prefix was credited: %+v %q", a, origin)
	}
	// A default route is a destination too.
	j2 := joiner()
	j2.Add(routeRec(2, "dhclient", RTMNewRoute, 4, "default", 1000))
	if a, _ := j2.Attribute(routeTo("new", "default", 4, 1050)); a == nil || a.Comm != "dhclient" {
		t.Fatalf("a default route must match a default request: %+v", a)
	}
	if a, _ := j2.Attribute(routeTo("new", "10.0.0.0/8", 4, 1050)); a != nil {
		t.Fatalf("a default-route request must not explain a /8: %+v", a)
	}
}

func TestARequestWithNoKnownDestinationOrInterfaceStillMatches(t *testing.T) {
	// A multipath route has no single output interface, and a request the kernel program
	// could not fully read has no destination: neither may rule the request out.
	j := joiner()
	j.Add(routeRec(5, "ip", RTMNewRoute, 0, "", 1000))
	if a, _ := j.Attribute(routeTo("new", "10.91.0.0/24", 4, 1050)); a == nil || a.Comm != "ip" {
		t.Fatalf("a request with unknown destination and interface must still match: %+v", a)
	}
}

func linkRec(tgid uint32, comm string, typ uint16, ifindex uint32, ifname string, flags uint16, ms int) Record {
	r := rec(tgid, comm, typ, ifindex, ms)
	r.IfName, r.Flags = ifname, flags
	return r
}

// The case a real kernel exposed: modern `ip link set dev X` sends index 0 and names
// the device in IFLA_IFNAME, so an index-only join treated it as "names no interface"
// and credited the peer's carrier loss to it.
func TestALinkRequestThatNamesItsDeviceOnlyByNameExplainsOnlyThatDevice(t *testing.T) {
	j := joiner()
	j.Add(linkRec(7, "ip", RTMNewLink, 0, "nlat1", 0x1|0x4, 1000)) // ip link set dev nlat1 down
	named := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "nlat1", InterfaceIndex: 5, ObservedAt: at(1020)}
	if a, _ := j.Attribute(named); a == nil || a.Comm != "ip" {
		t.Fatalf("the named device's change must be ip's: %+v", a)
	}
	peer := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "nlat0", InterfaceIndex: 4, ObservedAt: at(1020)}
	if a, origin := j.Attribute(peer); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("the peer's carrier loss was credited to ip: %+v %q", a, origin)
	}
}

func TestACreateRequestMatchesThePeerItAlsoCreates(t *testing.T) {
	// ip link add nlat0 type veth peer name nlat1: IFLA_IFNAME is nlat0, but nlat1 is created too.
	j := joiner()
	j.Add(linkRec(7, "ip", RTMNewLink, 0, "nlat0", NLMFCreate|0x1|0x200, 1000))
	for _, name := range []string{"nlat0", "nlat1"} {
		e := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: name, InterfaceIndex: 9, ObservedAt: at(1020)}
		if a, _ := j.Attribute(e); a == nil || a.Comm != "ip" {
			t.Fatalf("a create must explain %s, the peer included: %+v", name, a)
		}
	}
}

func TestAnIndexWinsOverAName(t *testing.T) {
	// When a request gives an index the name is not consulted.
	j := joiner()
	j.Add(linkRec(7, "ip", RTMSetLink, 5, "stale-name", 0x1, 1000))
	e := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "nlat1", InterfaceIndex: 5, ObservedAt: at(1020)}
	if a, _ := j.Attribute(e); a == nil {
		t.Fatal("a request naming ifindex 5 must explain a change on ifindex 5 whatever the name says")
	}
	// An event with no name cannot be ruled out by one.
	j2 := joiner()
	j2.Add(linkRec(8, "ip", RTMNewLink, 0, "nlat1", 0x1, 1000))
	anon := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", InterfaceIndex: 5, ObservedAt: at(1020)}
	if a, _ := j2.Attribute(anon); a == nil {
		t.Fatal("an event without a name must not be excluded by a request's name")
	}
}

func withMsgLen(r Record, n uint32) Record { r.Len = n; return r }

// What a real kernel showed: every `ip link` command first sends a bare RTM_NEWLINK
// (no index, no name, no attributes) to probe for kernel support. It changes nothing
// and must explain nothing, or whoever runs `ip link` is credited with every link change
// near it.
func TestIproute2sProbeExplainsNothing(t *testing.T) {
	j := joiner()
	j.Add(withMsgLen(linkRec(9, "ip", RTMNewLink, 0, "", 0x5, 1000), 32)) // the probe
	j.Add(linkRec(9, "ip", RTMNewLink, 13, "", 0x5, 1001))                // the real request, by index
	carrier := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "nlat0", InterfaceIndex: 14, ObservedAt: at(1040)}
	if a, origin := j.Attribute(carrier); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("the probe (or a request for another device) was credited with a carrier loss: %+v %q", a, origin)
	}
	real := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "nlat1", InterfaceIndex: 13, ObservedAt: at(1040)}
	if a, _ := j.Attribute(real); a == nil || a.Comm != "ip" || a.Confidence != models.NetlinkActorProbable {
		t.Fatalf("the real request must still explain its own device: %+v", a)
	}
}

func TestALinkRequestWithAttributesButNoNameWeReadIsUncertainNotKernel(t *testing.T) {
	// It has attributes (length 60) but no index and no IFLA_IFNAME we read: say an
	// alternative name. It may be about this device, so nobody can be named and "kernel"
	// must not be claimed either.
	j := joiner()
	j.Add(withMsgLen(linkRec(9, "ip", RTMSetLink, 0, "", 0x5, 1000), 60))
	e := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "eth0", InterfaceIndex: 2, ObservedAt: at(1040)}
	if a, origin := j.Attribute(e); a != nil || origin != "" {
		t.Fatalf("an uncertain request must leave the event unattributed: %+v %q", a, origin)
	}
	// An exact match elsewhere is stronger than an uncertain one.
	j.Add(linkRec(10, "netplan", RTMSetLink, 2, "", 0x5, 1010))
	if a, _ := j.Attribute(e); a == nil || a.Comm != "netplan" {
		t.Fatalf("an exact match must win over an uncertain request: %+v", a)
	}
}

func TestAMessageLengthOfZeroIsUnknownAndNotAProbe(t *testing.T) {
	// A record from a program that did not report the length (Len 0) must not be
	// discarded as a probe: unknown is not "bare".
	j := joiner()
	j.Add(linkRec(9, "ip", RTMNewLink, 0, "", 0x5, 1000))
	e := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "eth0", InterfaceIndex: 2, ObservedAt: at(1040)}
	if _, origin := j.Attribute(e); origin != "" {
		t.Fatalf("an unknown-length untargeted request must leave the event unattributed, got %q", origin)
	}
}

func inNetNS(r Record, ns uint32) Record { r.NetNS = ns; return r }

// Interface indexes are per network namespace. A pod's CNI setup issues requests for its
// own ifindex 3 while the host has an unrelated ifindex 3: they must not be confused.
func TestARequestInAnotherNetworkNamespaceNeverExplainsAChangeHere(t *testing.T) {
	const host, pod = 4026531840, 4026532999
	j := joiner()
	j.netns = host
	j.Add(inNetNS(linkRec(50, "cni-plugin", RTMSetLink, 3, "", 0x5, 1000), pod)) // the pod's eth0 is ifindex 3
	hostEvent := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", Interface: "eth3", InterfaceIndex: 3, ObservedAt: at(1030)}
	if a, origin := j.Attribute(hostEvent); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("a pod-namespace request was credited with a host change on the same ifindex: %+v %q", a, origin)
	}
	// The same request in the host namespace does explain it.
	j.Add(inNetNS(linkRec(51, "ip", RTMSetLink, 3, "", 0x5, 1000), host))
	if a, _ := j.Attribute(hostEvent); a == nil || a.Comm != "ip" || a.Confidence != models.NetlinkActorProbable {
		t.Fatalf("the host-namespace request must explain it, and only it: %+v", a)
	}
}

func TestAnUnknownNamespaceIsKeptAndAJoinerWithoutOneChecksNothing(t *testing.T) {
	const host = 4026531840
	j := joiner()
	j.netns = host
	j.Add(inNetNS(linkRec(1, "ip", RTMSetLink, 3, "", 0x5, 1000), 0)) // the kernel program could not read it
	e := models.NetlinkEvent{Kind: models.NetlinkKindLink, Action: "new", InterfaceIndex: 3, ObservedAt: at(1030)}
	if a, _ := j.Attribute(e); a == nil {
		t.Fatal("a request with an unreadable namespace must not be discarded")
	}
	j2 := joiner() // netns 0: no check
	j2.Add(inNetNS(linkRec(1, "ip", RTMSetLink, 3, "", 0x5, 1000), 4026532999))
	if a, _ := j2.Attribute(e); a == nil {
		t.Fatal("a joiner given no namespace must not filter")
	}
}
