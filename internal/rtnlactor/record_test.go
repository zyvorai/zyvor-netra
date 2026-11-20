// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package rtnlactor

import (
	"encoding/binary"
	"testing"
)

// event builds the bytes of a struct rtnl_event exactly as the kernel program
// lays it out.
func event(ts, cgroup uint64, tgid, pid uint32, typ uint16, comm string) []byte {
	return eventOn(ts, cgroup, tgid, pid, typ, 0, comm)
}

func eventOn(ts, cgroup uint64, tgid, pid uint32, typ uint16, ifindex uint32, comm string) []byte {
	return routeEvent(ts, cgroup, tgid, pid, typ, ifindex, comm, 0, 0, nil)
}

// routeEvent builds a struct rtnl_event the way the kernel program lays it out,
// including the route fields (family, dst_len, RTA_DST bytes).
func routeEvent(ts, cgroup uint64, tgid, pid uint32, typ uint16, ifindex uint32, comm string, family, dstLen uint8, dst []byte) []byte {
	return fullEvent(ts, cgroup, tgid, pid, typ, 0, ifindex, comm, family, dstLen, dst, "")
}

// fullEvent builds a struct rtnl_event byte for byte as bpf/netra_rtnl.c lays it out.
func fullEvent(ts, cgroup uint64, tgid, pid uint32, typ, flags uint16, ifindex uint32, comm string, family, dstLen uint8, dst []byte, ifname string) []byte {
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], ts)
	le.PutUint64(b[8:], cgroup)
	le.PutUint32(b[16:], tgid)
	le.PutUint32(b[20:], pid)
	le.PutUint16(b[24:], typ)
	le.PutUint16(b[26:], flags)
	le.PutUint32(b[28:], ifindex)
	b[32], b[33] = family, dstLen
	// nlmsg_len is at [36:40]; tests that care set it with withLen.
	copy(b[40:], comm)
	copy(b[56:], dst)
	copy(b[72:], ifname)
	return b
}

func TestParseDecodesTheKernelLayout(t *testing.T) {
	r, err := Parse(event(123456789, 4242, 999, 1001, RTMDelRoute, "calico-node"))
	if err != nil {
		t.Fatal(err)
	}
	if r.TS != 123456789 || r.CgroupID != 4242 || r.TGID != 999 || r.PID != 1001 || r.Type != RTMDelRoute || r.Comm != "calico-node" {
		t.Fatalf("record=%+v", r)
	}
}

func TestParseDecodesTheInterfaceIndex(t *testing.T) {
	r, err := Parse(eventOn(1, 2, 3, 4, RTMSetLink, 17, "ip"))
	if err != nil || r.IfIndex != 17 || r.Comm != "ip" {
		t.Fatalf("record=%+v err=%v", r, err)
	}
	if r, _ := Parse(event(1, 2, 3, 4, RTMNewRoute, "ip")); r.IfIndex != 0 {
		t.Fatalf("a route request names no interface, got %d", r.IfIndex)
	}
}

func TestParseRouteDestinationIsFormattedLikeTheRecorder(t *testing.T) {
	v4 := routeEvent(1, 2, 3, 4, RTMNewRoute, 7, "ip", afInet, 24, []byte{10, 91, 0, 0})
	if r, _ := Parse(v4); r.Dest != "10.91.0.0/24" || r.IfIndex != 7 {
		t.Fatalf("v4 record=%+v", r)
	}
	v6 := routeEvent(1, 2, 3, 4, RTMDelRoute, 0, "ip", afInet6, 32,
		[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if r, _ := Parse(v6); r.Dest != "2001:db8::/32" {
		t.Fatalf("v6 record=%+v", r)
	}
	// dst_len 0 with no RTA_DST is the default route, as the recorder calls it.
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewRoute, 0, "ip", afInet, 0, nil)); r.Dest != "default" {
		t.Fatalf("default route dest=%q", r.Dest)
	}
	// Not a route request: no destination.
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewAddr, 0, "ip", afInet, 24, []byte{10, 0, 0, 0})); r.Dest != "" {
		t.Fatalf("an address request has no route destination, got %q", r.Dest)
	}
	// An impossible prefix length or an unknown family is not guessed at.
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewRoute, 0, "ip", afInet, 40, []byte{10, 0, 0, 0})); r.Dest != "" {
		t.Fatalf("a /40 IPv4 prefix must not be formatted, got %q", r.Dest)
	}
	if r, _ := Parse(routeEvent(1, 2, 3, 4, RTMNewRoute, 0, "ip", 99, 24, []byte{10, 0, 0, 0})); r.Dest != "" {
		t.Fatalf("an unknown family must not be formatted, got %q", r.Dest)
	}
}

func TestParseDecodesTheFlagsAndTheDeviceNameOfALinkRequest(t *testing.T) {
	// `ip link set dev nlat1 down`: index 0, the device named in IFLA_IFNAME, no create flag.
	r, err := Parse(fullEvent(1, 2, 3, 4, RTMNewLink, 0x1|0x4, 0, "ip", 0, 0, nil, "nlat1"))
	if err != nil || r.IfName != "nlat1" || r.IfIndex != 0 || r.Flags&NLMFCreate != 0 {
		t.Fatalf("record=%+v err=%v", r, err)
	}
	// `ip link add nlat0 type veth peer name nlat1`: NLM_F_CREATE.
	r, _ = Parse(fullEvent(1, 2, 3, 4, RTMNewLink, NLMFCreate|0x1|0x200, 0, "ip", 0, 0, nil, "nlat0"))
	if r.Flags&NLMFCreate == 0 || r.IfName != "nlat0" {
		t.Fatalf("create record=%+v", r)
	}
	// The comm and the name come from different fields and must not bleed into each other.
	if r.Comm != "ip" {
		t.Fatalf("comm=%q", r.Comm)
	}
	// A 15-character name (the longest an interface can have) is read whole.
	r, _ = Parse(fullEvent(1, 2, 3, 4, RTMDelLink, 0, 0, "ip", 0, 0, nil, "abcdefghijklmno"))
	if r.IfName != "abcdefghijklmno" {
		t.Fatalf("name=%q", r.IfName)
	}
}

// withLen sets the nlmsg_len field of a built event.
func withLen(b []byte, n uint32) []byte {
	binary.LittleEndian.PutUint32(b[36:], n)
	return b
}

func TestParseDecodesTheMessageLength(t *testing.T) {
	r, err := Parse(withLen(fullEvent(1, 2, 3, 4, RTMNewLink, 0x5, 0, "ip", 0, 0, nil, ""), 32))
	if err != nil || r.Len != 32 {
		t.Fatalf("record=%+v err=%v", r, err)
	}
	// The length must not bleed into the comm or the name.
	if r.Comm != "ip" || r.IfName != "" {
		t.Fatalf("record=%+v", r)
	}
}

func TestParseDecodesTheNetworkNamespace(t *testing.T) {
	b := fullEvent(1, 2, 3, 4, RTMNewRoute, 0, 7, "ip", afInet, 24, []byte{10, 91, 0, 0}, "")
	binary.LittleEndian.PutUint32(b[88:], 4026531840)
	r, err := Parse(b)
	if err != nil || r.NetNS != 4026531840 {
		t.Fatalf("record=%+v err=%v", r, err)
	}
	// The namespace must not bleed into the fields before it.
	if r.IfName != "" || r.Comm != "ip" || r.Dest != "10.91.0.0/24" {
		t.Fatalf("record=%+v", r)
	}
}

func TestParseComm(t *testing.T) {
	// A full 15-character name has its NUL at byte 15; a 16-byte field with no NUL
	// (never produced by the kernel, but defensive) is taken whole.
	full := make([]byte, EventSize)
	copy(full[40:], "bpfintegration.")
	if r, _ := Parse(full); r.Comm != "bpfintegration." {
		t.Fatalf("comm=%q", r.Comm)
	}
	noNul := make([]byte, EventSize)
	copy(noNul[40:], "0123456789abcdef")
	if r, _ := Parse(noNul); r.Comm != "0123456789abcdef" {
		t.Fatalf("comm=%q", r.Comm)
	}
	if r, _ := Parse(event(1, 1, 1, 1, RTMNewLink, "")); r.Comm != "" {
		t.Fatalf("empty comm=%q", r.Comm)
	}
}

func TestParseRejectsAShortRecord(t *testing.T) {
	if _, err := Parse(make([]byte, EventSize-1)); err == nil {
		t.Fatal("a short record was accepted")
	}
	// A longer record (a future kernel program adding fields) still decodes the prefix.
	long := append(event(5, 6, 7, 8, RTMNewAddr, "ip"), make([]byte, 16)...)
	if r, err := Parse(long); err != nil || r.Comm != "ip" || r.TGID != 7 {
		t.Fatalf("long record: %+v %v", r, err)
	}
}

func TestEventSizeMatchesTheKernelStruct(t *testing.T) {
	// 8 ts + 8 cgroup + 4 tgid + 4 pid + 2 type + 2 flags + 4 ifindex + 1 family + 1 dst_len + 2 pad + 4 len +
	// 16 comm + 16 dst + 16 ifname + 4 netns + 4 pad.
	if EventSize != 8+8+4+4+2+2+4+1+1+2+4+16+16+16+4+4 {
		t.Fatalf("EventSize=%d", EventSize)
	}
}

func TestTypeNames(t *testing.T) {
	for typ, want := range map[uint16]string{
		RTMNewLink: "RTM_NEWLINK", RTMDelLink: "RTM_DELLINK", RTMSetLink: "RTM_SETLINK",
		RTMNewAddr: "RTM_NEWADDR", RTMDelAddr: "RTM_DELADDR", RTMNewRoute: "RTM_NEWROUTE",
		RTMDelRoute: "RTM_DELROUTE", RTMNewNeigh: "RTM_NEWNEIGH", RTMDelNeigh: "RTM_DELNEIGH", 99: "RTM_99",
	} {
		if got := TypeName(typ); got != want {
			t.Errorf("TypeName(%d)=%q, want %q", typ, got, want)
		}
	}
}
