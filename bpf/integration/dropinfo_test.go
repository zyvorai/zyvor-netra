// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/dropinfo"
	"github.com/zyvorai/netra/internal/tpformat"
)

// These tests load the real bpf/netra_dropinfo.o into a real kernel, relocate
// its sk_buff reads against that kernel's BTF, attach to skb:kfree_skb, cause
// genuine packet drops on loopback (an nft drop rule, a UDP datagram to a closed
// port, a frame nobody handles) and read the maps back. Nothing is mocked: a
// verifier rejection, a failed relocation, a wrong offset, or a tracepoint that
// does not fire all show up as a failure.

func testDropInfoObjectPath() string {
	if p := os.Getenv("NETRA_BPF_DROPINFO_TEST_OBJECT"); p != "" {
		return p
	}
	if _, err := os.Stat("/tmp/netra_dropinfo.o"); err == nil {
		return "/tmp/netra_dropinfo.o"
	}
	return filepath.Join(filepath.Dir(testObjectPath()), "netra_dropinfo.o")
}

func loadDropInfo(t *testing.T) *dropinfo.Sensor {
	t.Helper()
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("kernel has no BTF; the drop info sensor is unavailable here (that path is TestDropInfoWithoutBTF)")
	}
	s, err := dropinfo.Load(dropinfo.Options{ObjectPath: testDropInfoObjectPath()})
	if err != nil {
		t.Fatalf("load drop info sensor (verifier, relocation or attach failure?): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func dropSnap(t *testing.T, s *dropinfo.Sensor) *dropinfo.Snapshot {
	t.Helper()
	sn, err := s.Snapshot(10000, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return sn
}

// waitFlow polls until a flow satisfying match is present, or returns nil.
func waitFlow(t *testing.T, s *dropinfo.Sensor, match func(dropinfo.Flow) bool) (*dropinfo.Flow, *dropinfo.Snapshot) {
	t.Helper()
	var sn *dropinfo.Snapshot
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		sn = dropSnap(t, s)
		for i := range sn.Flows {
			if match(sn.Flows[i]) {
				return &sn.Flows[i], sn
			}
		}
	}
	return nil, sn
}

func TestDropInfoLoadsRelocatesAndAttaches(t *testing.T) {
	s := loadDropInfo(t)
	sn := dropSnap(t, s)
	if !sn.Attached {
		t.Fatal("snapshot says not attached")
	}
}

func TestDropInfoWithoutBTFReportsWhyAndAttachesNothing(t *testing.T) {
	_, err := dropinfo.Load(dropinfo.Options{ObjectPath: testDropInfoObjectPath(), BTFPath: "/nonexistent/vmlinux"})
	if err == nil || !strings.Contains(err.Error(), "BTF") {
		t.Fatalf("want an error naming BTF, got %v", err)
	}
}

// A UDP datagram to a port nobody listens on is dropped with NO_SOCKET; the
// tuple and the reason name (taken from this kernel's own table) must both be
// right, and the count exact.
func TestDropInfoUDPToClosedPortIsAttributedToTheTuple(t *testing.T) {
	s := loadDropInfo(t)
	// Reserve a port, then close it, so nothing listens.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()

	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srcPort := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	// A connected UDP socket that has been told "port unreachable" fails its
	// next write with ECONNREFUSED instead of sending, so count what was sent:
	// each datagram that left produced exactly one drop.
	var n uint64
	for i := 0; i < 10; i++ {
		if _, err := c.Write([]byte("nobody home")); err == nil {
			n++
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n == 0 {
		t.Fatal("no datagram was sent")
	}

	f, sn := waitFlow(t, s, func(f dropinfo.Flow) bool {
		return f.Family == "ipv4" && f.Proto == "udp" && f.SrcPort == srcPort && f.DstPort == uint16(port) && f.Reason == "NO_SOCKET"
	})
	if f == nil {
		t.Fatalf("no NO_SOCKET drop attributed to udp 127.0.0.1:%d -> :%d; totals=%+v flows=%+v", srcPort, port, sn.Totals, sn.Flows)
	}
	if f.Src != "127.0.0.1" || f.Dst != "127.0.0.1" {
		t.Errorf("addresses = %s -> %s, want 127.0.0.1 -> 127.0.0.1", f.Src, f.Dst)
	}
	if f.Count != n {
		t.Errorf("count = %d, want exactly the %d datagrams sent", f.Count, n)
	}
	if f.Location == "" || strings.HasPrefix(f.Location, "0x") {
		t.Errorf("location %q was not resolved to a kernel symbol", f.Location)
	}
	t.Logf("dropped by %s, reason %s", f.Location, f.Reason)
	if sn.Reasons["NO_SOCKET"] < n {
		t.Errorf("reason total NO_SOCKET = %d, want >= %d", sn.Reasons["NO_SOCKET"], n)
	}
	found := false
	for _, st := range sn.Sites {
		if st.Reason == "NO_SOCKET" && st.Location == f.Location {
			found = true
		}
	}
	if !found {
		t.Errorf("no site row for NO_SOCKET at %s: %+v", f.Location, sn.Sites)
	}
}

// A netfilter drop of a TCP SYN is attributed to the connection attempt, with
// the reason NETFILTER_DROP and the netfilter core as the dropping code.
func TestDropInfoNetfilterDropIsAttributedToTheConnection(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed; cannot induce a netfilter drop")
	}
	s := loadDropInfo(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	table := fmt.Sprintf("netra_drop_%d", os.Getpid())
	rules := fmt.Sprintf("table inet %s {\n chain in { type filter hook input priority 0; tcp dport %d drop; }\n}\n", table, port)
	if err := runNFT(t, rules); err != nil {
		t.Skipf("cannot install a drop rule (no nf_tables?): %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })

	c, err := net.DialTimeout("tcp4", ln.Addr().String(), 400*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatal("the dial succeeded although its SYN should be dropped")
	}

	f, sn := waitFlow(t, s, func(f dropinfo.Flow) bool {
		return f.Family == "ipv4" && f.Proto == "tcp" && f.DstPort == uint16(port) && f.Reason == "NETFILTER_DROP"
	})
	if f == nil {
		t.Fatalf("no NETFILTER_DROP attributed to tcp 127.0.0.1 -> :%d; totals=%+v flows=%+v", port, sn.Totals, sn.Flows)
	}
	if f.Src != "127.0.0.1" || f.Dst != "127.0.0.1" || f.SrcPort == 0 {
		t.Errorf("tuple = %s:%d -> %s:%d", f.Src, f.SrcPort, f.Dst, f.DstPort)
	}
	if !strings.Contains(f.Location, "nf_") {
		t.Errorf("dropping code = %q, want a netfilter function", f.Location)
	}
	t.Logf("dropped by %s", f.Location)
}

func TestDropInfoIPv6Tuples(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed; cannot induce a netfilter drop")
	}
	s := loadDropInfo(t)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	table := fmt.Sprintf("netra_drop6_%d", os.Getpid())
	rules := fmt.Sprintf("table inet %s {\n chain in { type filter hook input priority 0; tcp dport %d drop; }\n}\n", table, port)
	if err := runNFT(t, rules); err != nil {
		t.Skipf("cannot install a drop rule: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })

	if c, err := net.DialTimeout("tcp6", ln.Addr().String(), 400*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("the dial succeeded although its SYN should be dropped")
	}
	f, sn := waitFlow(t, s, func(f dropinfo.Flow) bool {
		return f.Family == "ipv6" && f.Proto == "tcp" && f.DstPort == uint16(port)
	})
	if f == nil {
		t.Fatalf("no IPv6 drop attributed to [::1]:%d; totals=%+v flows=%+v", port, sn.Totals, sn.Flows)
	}
	if f.Src != "::1" || f.Dst != "::1" {
		t.Errorf("addresses = %s -> %s, want ::1 -> ::1", f.Src, f.Dst)
	}
}

// A frame with an ethertype nobody handles is dropped before any IP header
// exists. It must be counted as a drop with NO tuple, never given a made-up one:
// this is the case the ethertype/IP-version cross-check exists for.
func TestDropInfoNonIPFrameIsCountedWithoutATuple(t *testing.T) {
	s := loadDropInfo(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo interface")
	}
	const ethertype = 0x88B5 // IEEE 802.1 local experimental; no handler registered
	// Protocol 0: send-only. A socket bound to the ethertype would receive its
	// own frame, and a frame somebody handles is not dropped.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		t.Skipf("cannot open AF_PACKET socket: %v", err)
	}
	defer syscall.Close(fd)
	frame := make([]byte, 60)
	frame[12], frame[13] = byte(ethertype>>8), byte(ethertype&0xff)
	// A payload that looks like an IPv4 header on purpose: a program that
	// guessed the family from the bytes would fabricate a tuple from it.
	frame[14] = 0x45
	copy(frame[26:30], []byte{10, 9, 8, 7})
	copy(frame[30:34], []byte{6, 5, 4, 3})
	addr := &syscall.SockaddrLinklayer{Protocol: htons(ethertype), Ifindex: lo.Index}
	for i := 0; i < 5; i++ {
		if err := syscall.Sendto(fd, frame, 0, addr); err != nil {
			t.Skipf("cannot inject a frame on lo: %v", err)
		}
	}

	f, sn := waitFlow(t, s, func(f dropinfo.Flow) bool { return f.Family == "" && f.Reason == "UNHANDLED_PROTO" })
	if f == nil {
		t.Fatalf("the unhandled frame was not counted as a tuple-less drop; totals=%+v flows=%+v", sn.Totals, sn.Flows)
	}
	if f.Src != "" || f.Dst != "" || f.SrcPort != 0 {
		t.Errorf("a non-IP frame got a tuple: %+v", *f)
	}
	for _, g := range sn.Flows {
		if g.Src == "10.9.8.7" || g.Dst == "6.5.4.3" {
			t.Fatalf("a tuple was fabricated from a non-IP frame: %+v", g)
		}
	}
	if sn.Totals.NoTuple == 0 && sn.Totals.NoHeader == 0 {
		t.Errorf("neither noTuple nor noHeader counted: %+v", sn.Totals)
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// The layout comes from the kernel's own format file, not a constant: a kernel
// whose record has no protocol field must fail cleanly instead of misreading.
func TestDropInfoRefusesALayoutItCannotReadSafely(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("kernel has no BTF")
	}
	_, err := dropinfo.Load(dropinfo.Options{
		ObjectPath: testDropInfoObjectPath(),
		ReadFormat: func(g, e string) (*tpformat.Format, error) {
			return tpformat.Parse("name: kfree_skb\nformat:\n\tfield:void * skbaddr;\toffset:8;\tsize:8;\tsigned:0;\n")
		},
	})
	if err == nil {
		t.Fatal("Load should refuse a record with no protocol field")
	}
}
