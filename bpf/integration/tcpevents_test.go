// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/tcpevents"
	"github.com/zyvorai/netra/internal/tpformat"
)

// These tests load the real bpf/netra_tcpevents.o into a real kernel, attach
// the four tracepoints using the offsets that kernel's own format files
// declare, generate genuine TCP traffic on loopback, and read the maps back.
// Nothing here is mocked: a verifier rejection, a wrong offset, or a tracepoint
// that does not fire all show up as a failure.

func testTCPEventsObjectPath() string {
	if p := os.Getenv("NETRA_BPF_TCPEVENTS_TEST_OBJECT"); p != "" {
		return p
	}
	if _, err := os.Stat("/tmp/netra_tcpevents.o"); err == nil {
		return "/tmp/netra_tcpevents.o"
	}
	return filepath.Join(filepath.Dir(testObjectPath()), "netra_tcpevents.o")
}

func loadTCPEvents(t *testing.T, read func(group, event string) (*tpformat.Format, error)) *tcpevents.Sensor {
	t.Helper()
	s, err := tcpevents.Load(tcpevents.Options{ObjectPath: testTCPEventsObjectPath(), ReadFormat: read})
	if err != nil {
		t.Fatalf("load TCP event sensors (verifier or attach failure?): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func snap(t *testing.T, s *tcpevents.Sensor) *tcpevents.Snapshot {
	t.Helper()
	sn, err := s.Snapshot(10000)
	if err != nil {
		t.Fatal(err)
	}
	return sn
}

func transitionCount(sn *tcpevents.Snapshot, from, to string) uint64 {
	for _, tr := range sn.Transitions {
		if tr.From == from && tr.To == to {
			return tr.Count
		}
	}
	return 0
}

// roundTrip opens n connections to a fresh listener on addr, exchanges a byte
// each way, and closes both ends cleanly. It returns the listener's port.
func roundTrip(t *testing.T, network, addr string, n int) int {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 1)
				if _, err := c.Read(b); err == nil {
					_, _ = c.Write(b)
				}
			}(c)
		}
	}()
	for i := 0; i < n; i++ {
		c, err := net.DialTimeout(network, ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, _ = c.Write([]byte{1})
		b := make([]byte, 1)
		_, _ = c.Read(b)
		_ = c.Close()
	}
	time.Sleep(300 * time.Millisecond) // let the FIN handshakes finish
	return port
}

func TestTCPEventsAllFourSensorsLoadAndAttach(t *testing.T) {
	s := loadTCPEvents(t, nil)
	if len(s.Attached()) != 4 || len(s.Skipped()) != 0 {
		t.Fatalf("attached=%v skipped=%v; want all four sensors running on a modern kernel", s.Attached(), s.Skipped())
	}
}

func TestTCPEventsStateTransitionsAreCounted(t *testing.T) {
	s := loadTCPEvents(t, nil)
	before := snap(t, s)
	const n = 20
	roundTrip(t, "tcp4", "127.0.0.1:0", n)
	after := snap(t, s)

	// Deterministic for every connection, whichever side happens to close first.
	for _, tc := range []struct {
		from, to string
		min      uint64
	}{
		{"LISTEN", "SYN_RECV", n},       // the server receives each SYN
		{"SYN_RECV", "ESTABLISHED", n},  // ...and completes the handshake
		{"SYN_SENT", "ESTABLISHED", n},  // every client connect
		{"ESTABLISHED", "FIN_WAIT1", n}, // at least one active closer per connection
	} {
		if got := transitionCount(after, tc.from, tc.to) - transitionCount(before, tc.from, tc.to); got < tc.min {
			t.Errorf("%s -> %s: +%d, want at least %d; transitions=%v", tc.from, tc.to, got, tc.min, after.Transitions)
		}
	}
	// Which side closes first is a race, so the passive-side states are not
	// asserted individually; but every close must end in CLOSE.
	closed := transitionCount(after, "FIN_WAIT2", "CLOSE") + transitionCount(after, "LAST_ACK", "CLOSE") + transitionCount(after, "CLOSING", "CLOSE") +
		transitionCount(after, "TIME_WAIT", "CLOSE")
	closedBefore := transitionCount(before, "FIN_WAIT2", "CLOSE") + transitionCount(before, "LAST_ACK", "CLOSE") + transitionCount(before, "CLOSING", "CLOSE") +
		transitionCount(before, "TIME_WAIT", "CLOSE")
	if closed-closedBefore < n {
		t.Errorf("only %d closes reached CLOSE for %d connections; transitions=%v", closed-closedBefore, n, after.Transitions)
	}
	if after.Totals.StateTransitions <= before.Totals.StateTransitions {
		t.Fatal("the transition total did not advance")
	}
	if after.Totals.ReadErrors != before.Totals.ReadErrors {
		t.Fatalf("the program failed to read %d state records: the offsets are wrong for this kernel", after.Totals.ReadErrors-before.Totals.ReadErrors)
	}
}

// A connection to a closed port makes the kernel answer with a RST. The client
// socket receives it, so tcp_receive_reset must attribute one reset to each
// dial's tuple, ending at the closed port. (The kernel's reply to a packet for
// a port with no socket is not reported by tcp_send_reset on Linux 6.8, so no
// send-side count is expected here; see the abortive-close test.)
func TestTCPEventsReceivedResetsAreAttributedToTheTuple(t *testing.T) {
	s := loadTCPEvents(t, nil)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing listens here any more

	for i := 0; i < 8; i++ {
		if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", closedPort), time.Second); err == nil {
			_ = c.Close()
			t.Fatal("connect to a closed port unexpectedly succeeded")
		}
	}
	time.Sleep(200 * time.Millisecond)

	sn := snap(t, s)
	var recv uint64
	for _, f := range sn.Flows {
		if f.Family == "ipv4" && f.Src == "127.0.0.1" && f.Dst == "127.0.0.1" && f.DstPort == uint16(closedPort) {
			recv += f.RSTReceived
		}
	}
	if recv < 8 {
		t.Errorf("tcp_receive_reset: %d resets attributed to a tuple ending at :%d, want 8 (one per dial); flows=%+v", recv, closedPort, sn.Flows)
	}
}

// A socket that closes abortively (SO_LINGER 0) sends a RST itself. That is the
// path tcp_send_reset reports, and the peer receives it: both directions must
// land on the right tuple, which only holds if each tracepoint's own offsets
// were used (tcp_send_reset and tcp_receive_reset lay their tuples out differently).
func TestTCPEventsAbortiveCloseIsAttributedInBothDirections(t *testing.T) {
	s := loadTCPEvents(t, nil)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	const n = 6
	go func() {
		for i := 0; i < n; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*net.TCPConn).SetLinger(0) // close() now sends a RST instead of a FIN
			_ = c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
		if err != nil {
			// The server aborts straight after accepting, so the RST can beat
			// connect() home. That is the very event under test, not a failure.
			if errors.Is(err, syscall.ECONNRESET) {
				continue
			}
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(make([]byte, 1)) // returns with ECONNRESET once the RST arrives
		_ = c.Close()
	}
	time.Sleep(200 * time.Millisecond)

	sn := snap(t, s)
	var sent, recv uint64
	for _, f := range sn.Flows {
		if f.Family != "ipv4" || f.Src != "127.0.0.1" || f.Dst != "127.0.0.1" {
			continue
		}
		if f.SrcPort == uint16(port) {
			sent += f.RSTSent // the server socket's own tuple
		}
		if f.DstPort == uint16(port) {
			recv += f.RSTReceived // the client socket's tuple
		}
	}
	if sent < n {
		t.Errorf("tcp_send_reset: %d resets attributed to a tuple starting at :%d, want %d; flows=%+v totals=%+v", sent, port, n, sn.Flows, sn.Totals)
	}
	if recv < n {
		t.Errorf("tcp_receive_reset: %d resets attributed to a tuple ending at :%d, want %d; flows=%+v", recv, port, n, sn.Flows)
	}
}

func runNFT(t *testing.T, script string) error {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Retransmits are made deterministic without netem: after the handshake the
// server's replies are dropped, so the client's data is never acknowledged and
// it retransmits on its RTO.
func TestTCPEventsRetransmitsAreAttributedToTheTuple(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed; cannot induce packet loss")
	}
	s := loadTCPEvents(t, nil)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(3 * time.Second)
	}()

	c, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	table := fmt.Sprintf("netra_test_%d", os.Getpid())
	rules := fmt.Sprintf("table ip %s {\n chain out { type filter hook output priority 0; tcp sport %d drop; }\n}\n", table, port)
	if err := runNFT(t, rules); err != nil {
		t.Skipf("cannot install a drop rule (no nf_tables?): %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "ip", table).Run() })

	_, _ = c.Write([]byte("data that will never be acknowledged"))
	deadline := time.Now().Add(6 * time.Second)
	var got uint64
	for time.Now().Before(deadline) && got == 0 {
		time.Sleep(200 * time.Millisecond)
		for _, f := range snap(t, s).Flows {
			if f.Family == "ipv4" && f.DstPort == uint16(port) && f.Src == "127.0.0.1" && f.Dst == "127.0.0.1" {
				got += f.Retransmits
			}
		}
	}
	if got == 0 {
		sn := snap(t, s)
		t.Fatalf("no retransmit attributed to 127.0.0.1 -> :%d; totals=%+v flows=%d", port, sn.Totals, len(sn.Flows))
	}
}

func TestTCPEventsIPv6Tuples(t *testing.T) {
	s := loadTCPEvents(t, nil)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	for i := 0; i < 6; i++ {
		if c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", closedPort), time.Second); err == nil {
			_ = c.Close()
		}
	}
	time.Sleep(200 * time.Millisecond)
	found := false
	for _, f := range snap(t, s).Flows {
		if f.Family == "ipv6" && f.Src == "::1" && f.Dst == "::1" && (f.SrcPort == uint16(closedPort) || f.DstPort == uint16(closedPort)) && f.RSTSent+f.RSTReceived > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no IPv6 reset flow for [::1]:%d", closedPort)
	}
}

// If the kernel lacks a field the program needs, the events must be counted as
// unreadable, never guessed at. Hiding the IPv6 arrays makes IPv6 events
// unreadable deterministically.
func TestTCPEventsMissingFieldsAreCountedNotMisread(t *testing.T) {
	strip := func(group, event string) (*tpformat.Format, error) {
		f, err := tpformat.Read(group, event)
		if err != nil {
			return nil, err
		}
		delete(f.Fields, "saddr_v6")
		delete(f.Fields, "daddr_v6")
		return f, nil
	}
	s := loadTCPEvents(t, strip)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	for i := 0; i < 6; i++ {
		if c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", closedPort), time.Second); err == nil {
			_ = c.Close()
		}
	}
	time.Sleep(200 * time.Millisecond)
	sn := snap(t, s)
	if sn.Totals.ReadErrors == 0 {
		t.Fatalf("IPv6 events with no address layout were not counted as read errors: %+v", sn.Totals)
	}
	// Where tcp_send_reset carries sockaddr-style blobs (Linux 6.17), its IPv6
	// address is inside the blob rather than in a saddr_v6 field, so stripping
	// the classic fields removes nothing from it and its IPv6 flows are
	// legitimately readable. Every other sensor must not produce an IPv6 flow.
	sockaddrSend := false
	if f, err := tpformat.Read("tcp", "tcp_send_reset"); err == nil {
		sockaddrSend = !f.Has("sport")
	}
	for _, f := range sn.Flows {
		if f.Family != "ipv6" {
			continue
		}
		if sockaddrSend && f.RSTSent > 0 && f.RSTReceived == 0 && f.Retransmits == 0 {
			continue
		}
		t.Fatalf("an IPv6 flow appeared although its addresses could not be read: %+v", f)
	}
}

func TestTCPEventsSkipsASensorWhoseTracepointIsMissing(t *testing.T) {
	missing := func(group, event string) (*tpformat.Format, error) {
		if event == "tcp_receive_reset" {
			return nil, fmt.Errorf("tracepoint %s:%s: not present", group, event)
		}
		return tpformat.Read(group, event)
	}
	s := loadTCPEvents(t, missing)
	if len(s.Attached()) != 3 || s.Skipped()["receive_reset"] == "" {
		t.Fatalf("attached=%v skipped=%v: the other three sensors must still run", s.Attached(), s.Skipped())
	}
}
