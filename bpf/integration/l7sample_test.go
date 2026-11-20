// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/zyvorai/netra/internal/l7sample"
)

func enableRunStats() (io.Closer, error) { return ebpf.EnableStats(unix.BPF_STATS_RUN_TIME) }

// These tests load the real bpf/netra_l7sample.o into a real kernel and verifier,
// attach it to a scratch cgroup that holds only the test process (so nothing else
// on the machine is sampled), and drive genuine TCP on loopback.

func testL7ObjectPath() string {
	if p := os.Getenv("NETRA_BPF_L7SAMPLE_TEST_OBJECT"); p != "" {
		return p
	}
	if _, err := os.Stat("/tmp/netra_l7sample.o"); err == nil {
		return "/tmp/netra_l7sample.o"
	}
	return filepath.Join(filepath.Dir(testObjectPath()), "netra_l7sample.o")
}

// scratchCgroup moves this process into a fresh cgroup v2 directory and back on
// cleanup, and returns the directory. Sockets created afterwards belong to it.
func scratchCgroup(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("no cgroup v2 hierarchy")
	}
	orig, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip(err)
	}
	origPath := "/sys/fs/cgroup" + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(orig)), "0::"))
	dir := fmt.Sprintf("/sys/fs/cgroup/netra-l7s-test-%d", os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
	}
	pid := []byte(strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), pid, 0o644); err != nil {
		_ = os.Remove(dir)
		t.Skipf("cannot move into the cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(origPath, "cgroup.procs"), pid, 0o644)
		_ = os.Remove(dir)
	})
	return dir
}

type captured struct {
	l7sample.Sample
	Data []byte // a copy: the sampler's buffer is reused
}

type l7Harness struct {
	s      *l7sample.Sampler
	mu     sync.Mutex
	got    []captured
	cancel context.CancelFunc
}

func startL7(t *testing.T, ports map[uint16]l7sample.Protocol, gap time.Duration) *l7Harness {
	t.Helper()
	dir := scratchCgroup(t)
	s, err := l7sample.Load(l7sample.Options{ObjectPath: testL7ObjectPath(), CgroupPath: dir, Ports: ports, MinGap: gap})
	if err != nil {
		t.Fatalf("load the L7 sampler (verifier or attach failure?): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &l7Harness{s: s, cancel: cancel}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, func(x l7sample.Sample) {
			h.mu.Lock()
			h.got = append(h.got, captured{Sample: x, Data: append([]byte(nil), x.Data...)})
			h.mu.Unlock()
		})
	}()
	t.Cleanup(func() { cancel(); <-done; _ = s.Close() })
	return h
}

func (h *l7Harness) samples() []captured {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]captured(nil), h.got...)
}

// waitFor polls until pred is true of the captured samples, or fails.
func (h *l7Harness) waitFor(t *testing.T, what string, pred func([]captured) bool) []captured {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if s := h.samples(); pred(s) {
			return s
		}
	}
	t.Fatalf("timed out waiting for %s; captured %d samples", what, len(h.samples()))
	return nil
}

// serve accepts one connection and answers every read with reply, until closed.
func serve(t *testing.T, network, addr string, reply []byte) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					_, _ = c.Write(reply)
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

func dialNoDelay(t *testing.T, network, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func roundTripOnce(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("no reply: %v", err)
	}
}

// findPort reserves a free port and releases it, so the test can configure it
// before anything listens there.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func TestL7SampleRedisRequestAndResponseAreCapturedAndClassified(t *testing.T) {
	port := freePort(t)
	h := startL7(t, map[uint16]l7sample.Protocol{uint16(port): l7sample.ProtoRedis}, 0)
	_, stop := serve(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), []byte("+PONG\r\n"))
	defer stop()

	req := []byte("*1\r\n$4\r\nPING\r\n")
	c := dialNoDelay(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	roundTripOnce(t, c, req)

	got := h.waitFor(t, "the request and the reply", func(s []captured) bool {
		var reqs, resps int
		for _, x := range s {
			if x.ToServer && bytes.Equal(x.Data, req) {
				reqs++
			}
			if !x.ToServer && bytes.Equal(x.Data, []byte("+PONG\r\n")) {
				resps++
			}
		}
		return reqs >= 2 && resps >= 2 // egress and ingress of each
	})

	var egressReq, ingressReq bool
	counters := l7sample.NewCounters()
	for _, x := range got {
		if x.Proto != l7sample.ProtoRedis {
			t.Fatalf("sample protocol = %v, want redis", x.Proto)
		}
		if x.CgroupID == 0 {
			t.Errorf("sample has no cgroup id: %+v", x.Sample)
		}
		if x.ToServer && x.DstPort != uint16(port) || !x.ToServer && x.SrcPort != uint16(port) {
			t.Errorf("ports %d->%d do not match toServer=%v for service port %d", x.SrcPort, x.DstPort, x.ToServer, port)
		}
		if x.Src.String() != "127.0.0.1" || x.Dst.String() != "127.0.0.1" {
			t.Errorf("addresses %s -> %s", x.Src, x.Dst)
		}
		if x.ToServer && bytes.Equal(x.Data, req) {
			egressReq = egressReq || x.Egress
			ingressReq = ingressReq || !x.Egress
		}
		counters.Observe(x.Sample)
	}
	if !egressReq || !ingressReq {
		t.Errorf("the request was seen egress=%v ingress=%v, want both directions", egressReq, ingressReq)
	}

	// The whole path: kernel bytes -> parser -> bounded counters.
	// One PING crossed the wire in two directions and was seen on both sides, so it
	// is one request in each role (the client's egress = issued, the server's
	// ingress = served), and never two in one number.
	byRole := map[string]l7sample.ProtoStats{}
	for _, p := range counters.Snapshot().Protocols {
		if p.Protocol == "redis" {
			byRole[p.Role] = p
		}
	}
	for _, role := range []string{l7sample.RoleServed, l7sample.RoleIssued} {
		r := byRole[role]
		if r.Requests != 1 || r.Responses != 1 || len(r.Ops) != 1 || r.Ops[0].Op != "PING" || r.Errors != 0 {
			t.Fatalf("%s: counters = %+v, want exactly 1 PING request and 1 response", role, r)
		}
	}

	st, err := h.s.KernelStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Eligible < 4 || st.Emitted < 4 || st.LoadFail != 0 || st.RingbufFull != 0 {
		t.Fatalf("kernel stats = %+v", st)
	}
}

// The payload copy uses fixed-size chunks with an overlapping last chunk. Every
// length must come back exactly, byte for byte, up to the 128-byte cap.
func TestL7SampleCapturesEveryPayloadLengthExactly(t *testing.T) {
	port := freePort(t)
	h := startL7(t, map[uint16]l7sample.Protocol{uint16(port): l7sample.ProtoRedis}, 0)
	_, stop := serve(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), []byte("K"))
	defer stop()
	c := dialNoDelay(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))

	for n := 1; n <= 140; n++ {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte('a' + (i*7+n)%26)
		}
		p[0] = byte(n) // distinguishes this length's segment from its neighbours
		roundTripOnce(t, c, p)

		want := p
		if n > l7sample.CopyMax {
			want = p[:l7sample.CopyMax]
		}
		h.waitFor(t, fmt.Sprintf("a %d-byte payload", n), func(s []captured) bool {
			for _, x := range s {
				if x.ToServer && x.Egress && bytes.Equal(x.Data, want) {
					return true
				}
			}
			return false
		})
	}
	// And nothing was silently lost or mangled by a failed load.
	if st, err := h.s.KernelStats(); err != nil || st.LoadFail != 0 {
		t.Fatalf("kernel stats = %+v err=%v", st, err)
	}
}

func TestL7SampleIgnoresPortsThatAreNotConfigured(t *testing.T) {
	configured := freePort(t)
	h := startL7(t, map[uint16]l7sample.Protocol{uint16(configured): l7sample.ProtoRedis}, 0)
	otherPort, stop := serve(t, "tcp4", "127.0.0.1:0", []byte("+OK\r\n"))
	defer stop()
	c := dialNoDelay(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", otherPort))
	for i := 0; i < 20; i++ {
		roundTripOnce(t, c, []byte("*1\r\n$4\r\nPING\r\n"))
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(h.samples()); n != 0 {
		t.Fatalf("%d samples from a port that is not configured", n)
	}
	if st, _ := h.s.KernelStats(); st.Eligible != 0 || st.Emitted != 0 {
		t.Fatalf("kernel counted traffic on an unconfigured port: %+v", st)
	}
}

func TestL7SampleRateLimitsPerFlowAndCountsWhatItSkips(t *testing.T) {
	port := freePort(t)
	h := startL7(t, map[uint16]l7sample.Protocol{uint16(port): l7sample.ProtoRedis}, 400*time.Millisecond)
	_, stop := serve(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), []byte("+OK\r\n"))
	defer stop()
	c := dialNoDelay(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	const n = 150
	start := time.Now()
	for i := 0; i < n; i++ {
		roundTripOnce(t, c, []byte("*1\r\n$4\r\nPING\r\n"))
	}
	elapsed := time.Since(start)
	time.Sleep(200 * time.Millisecond)

	st, err := h.s.KernelStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.RateLimited == 0 {
		t.Fatalf("nothing was rate limited: %+v", st)
	}
	// 4 directional flows (each of request/reply, egress/ingress) and a 400 ms gap.
	max := uint64(4 * (int(elapsed/(400*time.Millisecond)) + 2))
	if st.Emitted > max {
		t.Fatalf("emitted %d samples in %v with a 400ms gap (allowed about %d)", st.Emitted, elapsed, max)
	}
	if st.Eligible < 4*n {
		t.Fatalf("eligible = %d, want the %d round trips counted in all four directions", st.Eligible, n)
	}
	// Eligible = Emitted + RateLimited (+ losses): the counters must add up, or the
	// scale factor userspace derives would be wrong.
	if st.Eligible != st.Emitted+st.RateLimited+st.RingbufFull+st.LoadFail {
		t.Fatalf("counters do not add up: %+v", st)
	}
	_ = h
}

func TestL7SampleIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	h := startL7(t, map[uint16]l7sample.Protocol{uint16(port): l7sample.ProtoPostgres}, 0)
	_, stop := serve(t, "tcp6", fmt.Sprintf("[::1]:%d", port), []byte("Z\x00\x00\x00\x05I"))
	defer stop()
	c := dialNoDelay(t, "tcp6", fmt.Sprintf("[::1]:%d", port))
	roundTripOnce(t, c, []byte("Q\x00\x00\x00\x0dSELECT 1\x00"))

	// One request is seen twice: leaving the client (issued) and arriving at the
	// server (served). Wait until the *served* observation is in, not just the first
	// sample: on a slower kernel the egress sample can be delivered well before the
	// ingress one, and counting at that moment sees no served request at all.
	servedQuery := func(s []captured) bool {
		c := l7sample.NewCounters()
		v6 := false
		for _, x := range s {
			if x.ToServer && x.Src.To4() == nil && len(x.Data) > 0 && x.Data[0] == 'Q' {
				v6 = true
			}
			c.Observe(x.Sample)
		}
		if !v6 {
			return false
		}
		for _, p := range c.Snapshot().Protocols {
			if p.Protocol == "postgres" && p.Role == l7sample.RoleServed && p.Requests >= 1 {
				return true
			}
		}
		return false
	}
	got := h.waitFor(t, "an IPv6 query seen by the serving side", servedQuery)
	counters := l7sample.NewCounters()
	for _, x := range got {
		if x.Src.To4() != nil {
			t.Errorf("an IPv4 address on an IPv6 flow: %s", x.Src)
		}
		counters.Observe(x.Sample)
	}
	var pg l7sample.ProtoStats
	for _, p := range counters.Snapshot().Protocols {
		if p.Protocol == "postgres" && p.Role == l7sample.RoleServed {
			pg = p
		}
	}
	if pg.Requests != 1 || len(pg.Ops) != 1 || pg.Ops[0].Op != "SELECT" {
		t.Fatalf("postgres counters = %+v", pg)
	}
}

// An unrelated write to the same host must never be attributed to the service.
func TestL7SampleReadsNothingWhenNoPayloadIsCarried(t *testing.T) {
	port := freePort(t)
	h := startL7(t, map[uint16]l7sample.Protocol{uint16(port): l7sample.ProtoRedis}, 0)
	_, stop := serve(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), []byte("+OK\r\n"))
	defer stop()
	// Connect and close without sending: only handshake and FIN segments, no payload.
	for i := 0; i < 10; i++ {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(h.samples()); n != 0 {
		t.Fatalf("%d samples from connections that carried no data", n)
	}
	if st, _ := h.s.KernelStats(); st.Eligible != 0 {
		t.Fatalf("payload-less segments counted as eligible: %+v", st)
	}
	_ = io.EOF
}

// The program runs on every TCP segment in the cgroup it is attached to, so its
// per-packet cost is what a user pays. Measured with the kernel's own BPF run-time
// accounting: on traffic to a port that is NOT configured (the common case: a
// header parse and two map lookups), and on a configured port with the default
// 100 ms rate limit (mostly rate-limited). Always run, with a generous ceiling, so
// an order-of-magnitude regression is caught; NETRA_BPF_COST_N sets the count.
func TestL7SampleCostPerPacket(t *testing.T) {
	n := 20000
	if v, err := strconv.Atoi(os.Getenv("NETRA_BPF_COST_N")); err == nil && v > 0 {
		n = v
	}
	closer, err := enableRunStats()
	if err != nil {
		t.Skipf("cannot enable BPF run-time statistics: %v", err)
	}
	defer closer.Close()

	sampled := freePort(t)
	h := startL7(t, map[uint16]l7sample.Protocol{uint16(sampled): l7sample.ProtoRedis}, 100*time.Millisecond)
	measure := func(port int) (perRun time.Duration, runs uint64) {
		r0, s0, err := h.s.ProgramStats()
		if err != nil {
			t.Fatal(err)
		}
		c := dialNoDelay(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		req := []byte("*1\r\n$4\r\nPING\r\n")
		buf := make([]byte, 64)
		for i := 0; i < n; i++ {
			if _, err := c.Write(req); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(buf); err != nil {
				t.Fatal(err)
			}
		}
		r1, s1, err := h.s.ProgramStats()
		if err != nil {
			t.Fatal(err)
		}
		runs = r1 - r0
		if runs == 0 {
			t.Fatal("the program did not run")
		}
		return (s1 - s0) / time.Duration(runs), runs
	}

	other, stopOther := serve(t, "tcp4", "127.0.0.1:0", []byte("+PONG\r\n"))
	defer stopOther()
	_, stopSampled := serve(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", sampled), []byte("+PONG\r\n"))
	defer stopSampled()

	unconfigured, ur := measure(other)
	configured, cr := measure(sampled)
	t.Logf("unconfigured port : %v per program run (%d runs: header parse + two map lookups)", unconfigured, ur)
	t.Logf("configured, 100ms : %v per program run (%d runs: mostly rate-limited)", configured, cr)
	for name, d := range map[string]time.Duration{"unconfigured": unconfigured, "configured": configured} {
		if d > 30*time.Microsecond {
			t.Fatalf("%s: %v per packet is far beyond what a header parse and two lookups should cost", name, d)
		}
	}
}
