// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package listenq

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These tests talk to the real kernel's inet_diag: they open listeners, connect
// to them, and read the queues back. None needs root except the half-open case.

// rawListener listens on addr:0 with an exact backlog (net.Listen would use
// somaxconn) and never accepts. Returns its port.
func rawListener(t *testing.T, ip6 bool, backlog int) int {
	t.Helper()
	var fd int
	var err error
	var sa syscall.Sockaddr
	if ip6 {
		fd, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
		sa = &syscall.SockaddrInet6{Addr: [16]byte{15: 1}}
	} else {
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		sa = &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	}
	if err != nil {
		t.Skipf("cannot create socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, sa); err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	if err := syscall.Listen(fd, backlog); err != nil {
		t.Fatal(err)
	}
	got, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	switch a := got.(type) {
	case *syscall.SockaddrInet4:
		return a.Port
	case *syscall.SockaddrInet6:
		return a.Port
	}
	t.Fatal("unexpected sockaddr")
	return 0
}

func find(t *testing.T, port int) Listener {
	t.Helper()
	ls, err := Dump()
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	for _, l := range ls {
		if int(l.Port) == port {
			return l
		}
	}
	t.Fatalf("listener on port %d not in the dump of %d listeners", port, len(ls))
	return Listener{}
}

func dialAll(network, addr string, n int) (conns []net.Conn) {
	for i := 0; i < n; i++ {
		if c, err := net.DialTimeout(network, addr, 300*time.Millisecond); err == nil {
			conns = append(conns, c)
		}
	}
	return
}

func closeAll(cs []net.Conn) {
	for _, c := range cs {
		_ = c.Close()
	}
}

// A backlog-1 listener that never accepts holds two connections and then
// refuses: the exact state the kernel's ListenOverflows counter counts, here
// attributed to one listener.
func TestDumpSeesAFullAcceptQueue(t *testing.T) {
	port := rawListener(t, false, 1)
	conns := dialAll("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 5)
	defer closeAll(conns)
	if len(conns) != 2 {
		t.Fatalf("%d connections completed against a backlog-1 listener, want 2 (the kernel's own behaviour; the rest are refused)", len(conns))
	}
	got := find(t, port)
	if got.Family != "ipv4" || got.Addr != "127.0.0.1" || got.Max != 1 || got.Queue != 2 {
		t.Fatalf("listener = %+v, want ipv4 127.0.0.1 queue=2 max=1", got)
	}
	if !got.Full() || got.Pct() != 100 || !got.Saturated() {
		t.Fatalf("full=%v pct=%d saturated=%v, want a full queue", got.Full(), got.Pct(), got.Saturated())
	}
}

func TestDumpQueueDrainsWhenTheApplicationAccepts(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conns := dialAll("tcp4", ln.Addr().String(), 3)
	defer closeAll(conns)

	if got := find(t, port); got.Queue != 3 || got.Full() || got.Max < 128 {
		t.Fatalf("before accept: %+v, want queue=3, not full, a realistic backlog", got)
	}
	for i := 0; i < 3; i++ {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	if got := find(t, port); got.Queue != 0 {
		t.Fatalf("after accepting all: queue = %d, want 0", got.Queue)
	}
}

func TestDumpIPv6Listener(t *testing.T) {
	port := rawListener(t, true, 4)
	conns := dialAll("tcp6", fmt.Sprintf("[::1]:%d", port), 2)
	defer closeAll(conns)
	got := find(t, port)
	if got.Family != "ipv6" || got.Addr != "::1" || got.Queue != 2 || got.Max != 4 {
		t.Fatalf("listener = %+v, want ipv6 ::1 queue=2 max=4", got)
	}
}

// The Sampler over the real kernel end to end: pressure shows in the snapshot,
// the peak outlives the drain, and the histogram counts it.
func TestSamplerOnTheRealKernel(t *testing.T) {
	port := rawListener(t, false, 1)
	conns := dialAll("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 3)
	s := &Sampler{}
	sn, err := s.Sample(50)
	if err != nil {
		t.Fatal(err)
	}
	if sn.Full < 1 || sn.Buckets["full"] < 1 {
		t.Fatalf("snapshot missed a full listener: full=%d buckets=%v", sn.Full, sn.Buckets)
	}
	closeAll(conns) // the queued connections go away; the listener never accepted
	found := false
	for _, e := range sn.Top {
		if int(e.Port) == port {
			found = e.Peak == 2 && e.PeakPct == 100
		}
	}
	if !found {
		t.Fatalf("no top entry for :%d with peak 2 / 100%%: %+v", port, sn.Top)
	}
}

// procListeners reads the listening ports from /proc/net/tcp{,6}.
func procListeners() map[int]bool {
	out := map[int]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" { // 0A = TCP_LISTEN
				continue
			}
			var port int
			if _, err := fmt.Sscanf(fields[1][strings.LastIndex(fields[1], ":")+1:], "%X", &port); err == nil {
				out[port] = true
			}
		}
	}
	return out
}

// The dump and /proc/net/tcp are two non-atomic reads of a table that other
// processes (and, under `go test ./...`, other packages' tests) change at will, so
// "every port in /proc is in the dump" is a race: a listener can close between the
// reads. What must hold is narrower and exact: a listener that existed for the
// whole window, seen in /proc both before and after the dump, must be in the dump.
func TestDumpFindsEveryListenerTheKernelHas(t *testing.T) {
	// Hold a listener open ourselves so the intersection is never empty.
	held := rawListener(t, false, 8)
	before := procListeners()
	ls, err := Dump()
	if err != nil {
		t.Fatal(err)
	}
	after := procListeners()
	got := map[int]bool{}
	for _, l := range ls {
		got[int(l.Port)] = true
	}
	if !got[held] {
		t.Fatalf("the listener this test holds open (port %d) is missing from the dump", held)
	}
	stable := 0
	for p := range before {
		if !after[p] {
			continue // it came and went during the window: not required
		}
		stable++
		if !got[p] {
			t.Errorf("port %d was listening throughout (in /proc before and after) but is missing from the dump", p)
		}
	}
	if stable == 0 {
		t.Fatal("no listener was stable across the window, so nothing was checked")
	}
}

// Half-open connections need the handshake's last ACK to go missing, which
// needs nft and root; it runs in the privileged CI job and in a lab.
func TestDumpCountsHalfOpenConnections(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to install an nft rule (runs in the privileged ebpf job)")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	port := rawListener(t, false, 128)
	table := fmt.Sprintf("netra_lq_%d", os.Getpid())
	rules := fmt.Sprintf("table inet %s {\n chain in { type filter hook input priority 0;\n tcp dport %d tcp flags & (syn | ack) == ack drop\n }\n}\n", table, port)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot install a drop rule: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })

	// The client sees a completed handshake; the server never gets the final ACK.
	conns := dialAll("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 3)
	defer closeAll(conns)
	if len(conns) != 3 {
		t.Fatalf("%d of 3 connects completed", len(conns))
	}
	got := find(t, port)
	if got.SynRecv != 3 || got.Queue != 0 {
		t.Fatalf("listener = %+v, want 3 half-open and an empty accept queue", got)
	}
}

// Recreates the race that made the cross-check flaky: other listeners opening and
// closing continuously while the dump is compared against /proc. A listener that
// was present for the whole window must always be in the dump, however much churn
// there is around it; the previous form of the check failed under `go test ./...`
// when neighbouring packages' tests happened to open and close listeners.
func TestDumpIsCorrectWhileOtherListenersChurn(t *testing.T) {
	held := rawListener(t, false, 8)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if ln, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
					_ = ln.Close()
				}
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()

	// inet_diag does not dump the listener hash atomically: a socket that stays in place
	// can still be skipped once when its neighbours in the same bucket are added or removed
	// mid-dump (seen on a CI runner: 1 miss in 14 rounds under this deliberately savage
	// churn). What the sampler needs, and what this asserts, is that a listener that was
	// there the whole time is never MISSING PERSISTENTLY: a fresh dump right away has it.
	// Each round therefore allows a few immediate re-dumps, and counts the misses so a
	// regression that made them routine (a broken dump loop) still fails.
	const attempts, maxMissRounds = 5, 20
	missRounds := 0
	for round := 0; round < 200; round++ {
		var lastErr string
		ok := false
		missed := false
		for try := 0; try < attempts && !ok; try++ {
			before := procListeners()
			ls, err := Dump()
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			after := procListeners()
			got := map[int]bool{}
			for _, l := range ls {
				got[int(l.Port)] = true
			}
			lastErr = ""
			if !got[held] {
				lastErr = fmt.Sprintf("the long-lived listener (port %d) is missing from the dump", held)
			}
			for p := range before {
				if lastErr == "" && after[p] && !got[p] {
					lastErr = fmt.Sprintf("port %d was listening throughout but is missing from the dump", p)
				}
			}
			if lastErr == "" {
				ok = true
			} else {
				missed = true
			}
		}
		if !ok {
			t.Fatalf("round %d: still %s after %d immediate re-dumps", round, lastErr, attempts)
		}
		if missed {
			missRounds++
		}
	}
	if missRounds > maxMissRounds {
		t.Fatalf("%d of 200 dumps missed a stable listener at least once (more than %d): the dump is not merely non-atomic, it is unreliable", missRounds, maxMissRounds)
	}
	t.Logf("%d of 200 dumps missed a stable listener once and found it on an immediate re-dump", missRounds)
}
