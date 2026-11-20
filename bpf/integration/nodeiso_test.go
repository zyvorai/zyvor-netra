// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/nodeiso"
)

// These load the real bpf/netra_nodeiso.o, publish policies through the same
// nodeiso.Isolator.Apply the agent uses, and run crafted frames through the
// verified program with BPF_PROG_TEST_RUN. The rule table and cases are
// ported from FluxVM's scripts/test-pod-policy-verdict.py (partial-byte
// prefixes such as /12 and /45, protocol and port filters, /0, /32, both
// families), plus what is specific to node isolation: shadow never drops,
// replies and exempt classes pass, and a generation swap replaces the rule
// set atomically.

const tcActUnspec = 0xFFFFFFFF // TCX_NEXT, returned as an unsigned retval

func testNodeIsoObjectPath() string {
	if p := os.Getenv("NETRA_BPF_NODEISO_TEST_OBJECT"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(testObjectPath()), "netra_nodeiso.o")
}

func eth(proto uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(b[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(b[12:14], proto)
	return b
}

func l4tcp(sport, dport uint16, flags byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	b[12], b[13] = 5<<4, flags
	return b
}

func l4udp(sport, dport uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], 8)
	return b
}

func v4(proto byte, dst string, l4 []byte) []byte {
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	copy(ip[12:16], net.ParseIP("10.98.0.2").To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	return pad64(append(append(eth(0x0800), ip...), l4...))
}

func v6(proto byte, dst string, l4 []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 6 << 4
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(l4)))
	ip[6], ip[7] = proto, 64
	copy(ip[8:24], net.ParseIP("fd98::2").To16())
	copy(ip[24:40], net.ParseIP(dst).To16())
	return pad64(append(append(eth(0x86DD), ip...), l4...))
}

func pad64(b []byte) []byte {
	for len(b) < 64 {
		b = append(b, 0)
	}
	return b
}

var nodeIsoRules = []models.NodeIsolationRule{
	{CIDR: "10.96.0.0/12"}, // any proto, partial byte
	{CIDR: "192.168.5.0/24", Protocol: "tcp", PortFrom: 443, PortTo: 443}, // TCP/443 only
	{CIDR: "172.16.0.1/32", Protocol: "udp"},                              // UDP any port, exact host
	{CIDR: "fd00:1::/32"},                                                 // any proto, byte-aligned v6
	{CIDR: "2001:db8:1230::/45", Protocol: "tcp", PortFrom: 8000, PortTo: 8100},
	{CIDR: "0.0.0.0/0", Protocol: "udp", PortFrom: 53, PortTo: 53}, // DNS anywhere
	{CIDR: "198.51.100.0/24", PortFrom: 8443, PortTo: 8443},        // any of TCP/UDP on one port
}

const syn = 0x02

var nodeIsoCases = []struct {
	name    string
	frame   []byte
	allowed bool
}{
	{"v4 udp 10.96.1.1 (in /12)", v4(17, "10.96.1.1", l4udp(1001, 9)), true},
	{"v4 udp 10.111.255.255 (last in /12)", v4(17, "10.111.255.255", l4udp(1002, 9)), true},
	{"v4 udp 10.112.0.1 (just past /12)", v4(17, "10.112.0.1", l4udp(1003, 9)), false},
	{"v4 udp 10.95.255.255 (just before /12)", v4(17, "10.95.255.255", l4udp(1004, 9)), false},
	{"v4 tcp syn 192.168.5.9:443", v4(6, "192.168.5.9", l4tcp(1006, 443, syn)), true},
	{"v4 tcp syn 192.168.5.9:444 (port miss)", v4(6, "192.168.5.9", l4tcp(1007, 444, syn)), false},
	{"v4 tcp syn 192.168.6.9:443 (prefix miss)", v4(6, "192.168.6.9", l4tcp(1008, 443, syn)), false},
	{"v4 udp 192.168.5.9:443 (proto miss)", v4(17, "192.168.5.9", l4udp(1009, 443)), false},
	{"v4 udp 172.16.0.1 (/32 exact)", v4(17, "172.16.0.1", l4udp(1010, 9)), true},
	{"v4 udp 172.16.0.2 (/32 miss)", v4(17, "172.16.0.2", l4udp(1011, 9)), false},
	{"v4 udp 8.8.8.8:53 (/0 + port)", v4(17, "8.8.8.8", l4udp(1012, 53)), true},
	{"v4 udp 8.8.8.8:54 (/0, port miss)", v4(17, "8.8.8.8", l4udp(1013, 54)), false},
	{"v4 tcp syn 198.51.100.7:8443 (any-proto port)", v4(6, "198.51.100.7", l4tcp(1014, 8443, syn)), true},
	{"v4 udp 198.51.100.7:8443 (any-proto port)", v4(17, "198.51.100.7", l4udp(1015, 8443)), true},
	{"v4 gre 198.51.100.7 (port rule needs ports)", v4(47, "198.51.100.7", make([]byte, 8)), false},
	{"v6 tcp syn fd00:1::5 (byte-aligned /32)", v6(6, "fd00:1::5", l4tcp(1016, 80, syn)), true},
	{"v6 udp fd00:1::5 (any proto)", v6(17, "fd00:1::5", l4udp(1017, 80)), true},
	{"v6 tcp syn fd00:2::5 (miss)", v6(6, "fd00:2::5", l4tcp(1018, 80, syn)), false},
	{"v6 tcp syn 2001:db8:1234::1:8050 (/45 in)", v6(6, "2001:db8:1234::1", l4tcp(1019, 8050, syn)), true},
	{"v6 tcp syn 2001:db8:1237:ffff::1:8050 (last in /45)", v6(6, "2001:db8:1237:ffff::1", l4tcp(1020, 8050, syn)), true},
	{"v6 tcp syn 2001:db8:1238::1:8050 (just past /45)", v6(6, "2001:db8:1238::1", l4tcp(1021, 8050, syn)), false},
	{"v6 tcp syn 2001:db8:1234::1:7999 (port low)", v6(6, "2001:db8:1234::1", l4tcp(1022, 7999, syn)), false},
	{"v6 tcp syn 2001:db8:1234::1:8101 (port high)", v6(6, "2001:db8:1234::1", l4tcp(1023, 8101, syn)), false},
	// Always pass, whatever the rules say.
	{"v4 tcp syn-ack reply to an inbound connection", v4(6, "203.0.113.9", l4tcp(22, 50000, syn|0x10)), true},
	{"v4 tcp established ack", v4(6, "203.0.113.9", l4tcp(40000, 9999, 0x10)), true},
	{"v4 icmp", v4(1, "203.0.113.9", make([]byte, 8)), true},
	{"v6 icmpv6 (neighbor discovery)", v6(58, "fe80::1", make([]byte, 8)), true},
	{"v4 dhcp client", v4(17, "255.255.255.255", l4udp(68, 67)), true},
	{"v4 udp from exempt local port 22", v4(17, "203.0.113.9", l4udp(22, 40000)), true},
}

func loadNodeIso(t *testing.T) *nodeiso.Isolator {
	t.Helper()
	iso, err := nodeiso.Load(nodeiso.Options{ObjectPath: testNodeIsoObjectPath(), LoadOnly: true})
	if err != nil {
		t.Fatalf("load node isolation (verifier rejection?): %v", err)
	}
	t.Cleanup(func() { _ = iso.Close() })
	return iso
}

func runFrame(t *testing.T, iso *nodeiso.Isolator, frame []byte) uint32 {
	t.Helper()
	ret, _, err := iso.Program().Test(frame)
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret
}

func TestNodeIsolationVerdicts(t *testing.T) {
	iso := loadNodeIso(t)
	for _, c := range nodeIsoCases {
		if got := runFrame(t, iso, c.frame); got != tcActUnspec {
			t.Fatalf("%s: no policy must pass everything, got %d", c.name, got)
		}
	}
	until := time.Now().Add(time.Hour)
	spec := &models.NodeIsolationSpec{PolicyID: "p", Revision: 1, Mode: models.NodeIsolationEnforce, LeaseUntil: &until, Rules: nodeIsoRules, ExemptLocalPorts: []uint16{22}}
	if err := iso.Apply(spec, nil, ""); err != nil {
		t.Fatal(err)
	}
	blocked := uint64(0)
	for _, c := range nodeIsoCases {
		want := uint32(tcActShot)
		if c.allowed {
			want = tcActUnspec
		} else {
			blocked++
		}
		if got := runFrame(t, iso, c.frame); got != want {
			t.Errorf("enforce %-52s got %d want %d", c.name, got, want)
		}
	}
	st, err := iso.Snapshot(50)
	if err != nil {
		t.Fatal(err)
	}
	if st.Blocked != blocked || st.WouldBlock != 0 || st.Mode != "enforce" || len(st.Top) == 0 {
		t.Fatalf("enforce counters: %+v (want %d blocked)", st, blocked)
	}

	// Shadow: same evaluation, nothing dropped, would-block counted.
	if err := iso.Apply(spec, nil, "controller stale"); err != nil {
		t.Fatal(err)
	}
	for _, c := range nodeIsoCases {
		if got := runFrame(t, iso, c.frame); got != tcActUnspec {
			t.Errorf("shadow must never drop: %s got %d", c.name, got)
		}
	}
	st, _ = iso.Snapshot(50)
	if st.WouldBlock != blocked || st.Blocked != blocked || st.Mode != "shadow" || st.Demoted != "controller stale" {
		t.Fatalf("shadow counters: %+v", st)
	}
}

func TestNodeIsolationGenerationSwap(t *testing.T) {
	iso := loadNodeIso(t)
	until := time.Now().Add(time.Hour)
	first := &models.NodeIsolationSpec{PolicyID: "p", Revision: 1, Mode: models.NodeIsolationEnforce, LeaseUntil: &until, Rules: []models.NodeIsolationRule{{CIDR: "10.0.0.0/8"}}}
	if err := iso.Apply(first, nil, ""); err != nil {
		t.Fatal(err)
	}
	a, b := v4(17, "10.1.2.3", l4udp(1000, 9)), v4(17, "192.0.2.1", l4udp(1000, 9))
	if runFrame(t, iso, a) != tcActUnspec || runFrame(t, iso, b) != tcActShot {
		t.Fatal("first policy")
	}
	second := &models.NodeIsolationSpec{PolicyID: "p", Revision: 2, Mode: models.NodeIsolationEnforce, LeaseUntil: &until, Rules: []models.NodeIsolationRule{{CIDR: "192.0.2.0/24"}}}
	if err := iso.Apply(second, []models.NodeIsolationRule{{CIDR: "203.0.113.5/32", Protocol: "tcp", PortFrom: 30870}}, ""); err != nil {
		t.Fatal(err)
	}
	if runFrame(t, iso, a) != tcActShot || runFrame(t, iso, b) != tcActUnspec {
		t.Fatal("the swap must replace the whole rule set: old rules gone, new ones live")
	}
	if runFrame(t, iso, v4(6, "203.0.113.5", l4tcp(40000, 30870, syn))) != tcActUnspec {
		t.Fatal("implicit controller rule")
	}
	if err := iso.Apply(nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if runFrame(t, iso, a) != tcActUnspec {
		t.Fatal("clearing the policy passes everything again")
	}
}
