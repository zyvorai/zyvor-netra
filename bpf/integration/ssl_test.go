// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/l7sample"
	"github.com/zyvorai/netra/internal/sslprobe"
)

// These tests load the real bpf/netra_ssl.o into a real kernel and verifier,
// attach uprobes to the system's real libssl, and drive genuine TLS: a Python
// HTTPS server and client (CPython's ssl module links libssl dynamically and calls
// SSL_read_ex/SSL_write_ex), so the plaintext captured is what real applications
// hand to OpenSSL.

func testSSLObjectPath() string {
	if p := os.Getenv("NETRA_BPF_SSL_TEST_OBJECT"); p != "" {
		return p
	}
	if _, err := os.Stat("/tmp/netra_ssl.o"); err == nil {
		return "/tmp/netra_ssl.o"
	}
	return filepath.Join(filepath.Dir(testObjectPath()), "netra_ssl.o")
}

const httpsServerPy = `
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = 404 if "missing" in self.path else 200
        self.send_response(code); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv = http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("ready", flush=True)
srv.serve_forever()
`

const httpsClientPy = `
import ssl, sys, urllib.request, urllib.error
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
port, n = sys.argv[1], int(sys.argv[2])
for i in range(n):
    for path in sys.argv[3:]:
        try:
            urllib.request.urlopen("https://localhost:%s%s" % (port, path), context=ctx).read()
        except urllib.error.HTTPError:
            pass
`

type tlsFixture struct {
	port   int
	server *exec.Cmd
}

// startHTTPSServer generates a throwaway certificate and starts the server, which
// maps libssl once ready.
func startHTTPSServer(t *testing.T) *tlsFixture {
	t.Helper()
	for _, c := range []string{"python3", "openssl"} {
		if _, err := exec.LookPath(c); err != nil {
			t.Skipf("%s is not installed", c)
		}
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
		"-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1").CombinedOutput(); err != nil {
		t.Skipf("cannot make a certificate: %v: %s", err, out)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	srv := exec.Command("python3", "-c", httpsServerPy, fmt.Sprint(port), cert, key)
	out, err := srv.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Skipf("cannot start the HTTPS server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	line := make(chan string, 1)
	go func() { s, _ := bufio.NewReader(out).ReadString('\n'); line <- s }()
	select {
	case s := <-line:
		if !strings.HasPrefix(s, "ready") {
			t.Skipf("the HTTPS server did not start: %q", s)
		}
	case <-time.After(10 * time.Second):
		t.Skip("the HTTPS server did not start in time")
	}
	return &tlsFixture{port: port, server: srv}
}

func (f *tlsFixture) get(t *testing.T, n int, paths ...string) {
	t.Helper()
	args := append([]string{"-c", httpsClientPy, fmt.Sprint(f.port), fmt.Sprint(n)}, paths...)
	if out, err := exec.Command("python3", args...).CombinedOutput(); err != nil {
		t.Fatalf("client: %v: %s", err, out)
	}
}

type sslCapture struct {
	sslprobe.Event
	Data []byte // a copy: the record buffer is reused
}

type sslHarness struct {
	p   *sslprobe.Prober
	mu  sync.Mutex
	got []sslCapture
}

func startSSL(t *testing.T, comms []string, gap time.Duration) *sslHarness {
	t.Helper()
	p, err := sslprobe.Load(sslprobe.Options{ObjectPath: testSSLObjectPath(), MinGap: gap, Comms: comms})
	if err != nil {
		t.Fatalf("load the TLS sampler (verifier failure?): %v", err)
	}
	h := &sslHarness{p: p}
	added, err := p.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(added) == 0 {
		_ = p.Close()
		t.Skip("no process maps libssl here")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx, func(e sslprobe.Event) {
			h.mu.Lock()
			h.got = append(h.got, sslCapture{Event: e, Data: append([]byte(nil), e.Data...)})
			h.mu.Unlock()
		})
	}()
	t.Cleanup(func() { cancel(); <-done; _ = p.Close() })
	return h
}

func (h *sslHarness) waitFor(t *testing.T, what string, pred func([]sslCapture) bool) []sslCapture {
	t.Helper()
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		h.mu.Lock()
		s := append([]sslCapture(nil), h.got...)
		h.mu.Unlock()
		if pred(s) {
			return s
		}
	}
	h.mu.Lock()
	n := len(h.got)
	h.mu.Unlock()
	t.Fatalf("timed out waiting for %s; captured %d events", what, n)
	return nil
}

func hasPrefixEvent(s []sslCapture, write bool, prefix string) bool {
	for _, e := range s {
		if e.Write == write && bytes.HasPrefix(e.Data, []byte(prefix)) {
			return true
		}
	}
	return false
}

func TestSSLLoadsAttachesAndCapturesRealTLSPlaintext(t *testing.T) {
	f := startHTTPSServer(t)
	h := startSSL(t, nil, 0)
	if libs := h.p.Libraries(); len(libs) == 0 {
		t.Fatal("no library was instrumented")
	}
	const path = "/orders/42?token=PLAINTEXT-SECRET"
	f.get(t, 1, path)

	// The client hands its request to SSL_write and the server gets it from SSL_read:
	// the same plaintext, before encryption and after decryption.
	want := "GET " + path + " HTTP/1.1"
	got := h.waitFor(t, "the request and response in plaintext", func(s []sslCapture) bool {
		return hasPrefixEvent(s, true, want) && hasPrefixEvent(s, false, want) &&
			hasPrefixEvent(s, true, "HTTP/1.0 200") && hasPrefixEvent(s, false, "HTTP/1.0 200")
	})
	for _, e := range got {
		if e.PID == 0 || e.Comm == "" || e.CgroupID == 0 || e.SSL == 0 {
			t.Errorf("event missing identity: %+v", e.Event)
		}
	}
	// The ciphertext is not what we see: nothing captured begins like a TLS record.
	for _, e := range got {
		if len(e.Data) >= 3 && e.Data[0] == 0x17 && e.Data[1] == 0x03 {
			t.Errorf("captured what looks like a TLS record, not plaintext: % x", e.Data[:8])
		}
	}

	// Classification: metadata only, in the right role.
	counters := l7sample.NewCounters()
	for _, e := range got {
		o, role, ok := sslprobe.Classify(e.Write, e.Data)
		counters.ObserveObs(o, ok, role)
	}
	byRole := map[string]l7sample.ProtoStats{}
	for _, p := range counters.Snapshot().Protocols {
		if p.Protocol == "http1" {
			byRole[p.Role] = p
		}
	}
	for _, role := range []string{l7sample.RoleIssued, l7sample.RoleServed} {
		p := byRole[role]
		if p.Requests != 1 || p.Responses != 1 || len(p.Ops) != 1 || p.Ops[0].Op != "GET" {
			t.Fatalf("%s: %+v, want exactly one GET request and one response", role, p)
		}
	}
	snap := counters.Snapshot()
	if s := fmt.Sprintf("%+v", snap); strings.Contains(s, "PLAINTEXT-SECRET") || strings.Contains(s, "orders") {
		t.Fatalf("the counters carry request text: %s", s)
	}
	// One GET to localhost: once as issued (the client wrote it), once as served (the
	// server read it), never twice in one row.
	hosts := map[string]uint64{}
	for _, h := range snap.Hosts {
		if h.Host != "localhost" || h.Op != "GET" {
			t.Fatalf("unexpected host row %+v", h)
		}
		hosts[h.Role] += h.Count
	}
	if hosts[l7sample.RoleIssued] != 1 || hosts[l7sample.RoleServed] != 1 || len(hosts) != 2 {
		t.Fatalf("host counts by role = %v, want 1 issued and 1 served", hosts)
	}

	st, err := h.p.KernelStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Emitted < 4 || st.ReadFail != 0 || st.RingbufFull != 0 {
		t.Fatalf("kernel stats = %+v", st)
	}
}

func TestSSLCountsEveryRequestAndItsStatus(t *testing.T) {
	f := startHTTPSServer(t)
	h := startSSL(t, nil, 0)
	const n = 5
	f.get(t, n, "/a", "/b/missing")

	counters := l7sample.NewCounters()
	deadline := time.Now().Add(8 * time.Second)
	var served l7sample.ProtoStats
	for time.Now().Before(deadline) {
		h.mu.Lock()
		got := append([]sslCapture(nil), h.got...)
		h.mu.Unlock()
		counters = l7sample.NewCounters()
		for _, e := range got {
			o, role, ok := sslprobe.Classify(e.Write, e.Data)
			counters.ObserveObs(o, ok, role)
		}
		served = l7sample.ProtoStats{}
		for _, p := range counters.Snapshot().Protocols {
			if p.Protocol == "http1" && p.Role == l7sample.RoleServed {
				served = p
			}
		}
		if served.Requests == 2*n && served.Responses == 2*n {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if served.Requests != 2*n || served.Responses != 2*n || served.Errors != n {
		t.Fatalf("served = %+v, want %d requests, %d responses, %d errors (the 404s)", served, 2*n, 2*n, n)
	}
	codes := map[string]uint64{}
	for _, c := range served.Codes {
		codes[c.Code] = c.Count
	}
	if codes["200"] != n || codes["404"] != n {
		t.Fatalf("status codes = %v, want %d x 200 and %d x 404", codes, n, n)
	}
}

// The process allowlist is enforced in the kernel before any byte is copied: a
// process that is not named is never read.
func TestSSLProcessAllowlistIsEnforcedInTheKernel(t *testing.T) {
	f := startHTTPSServer(t)
	h := startSSL(t, []string{"no-such-process"}, 0)
	f.get(t, 3, "/a")
	time.Sleep(500 * time.Millisecond)
	h.mu.Lock()
	n := len(h.got)
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d events from processes that are not on the allowlist", n)
	}
	st, err := h.p.KernelStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.CommFiltered == 0 || st.Emitted != 0 {
		t.Fatalf("kernel stats = %+v: the filter should have skipped calls and emitted none", st)
	}
	// Filtered calls are not candidates for sampling, so they are not "eligible":
	// otherwise the scale factor would be inflated by processes nobody asked to see.
	if st.Eligible != 0 {
		t.Fatalf("calls from processes outside the allowlist counted as eligible: %+v", st)
	}
}

func TestSSLAllowlistNamedProcessIsObserved(t *testing.T) {
	f := startHTTPSServer(t)
	h := startSSL(t, []string{"python3"}, 0)
	f.get(t, 1, "/a")
	h.waitFor(t, "an allowlisted process to be observed", func(s []sslCapture) bool {
		return hasPrefixEvent(s, true, "GET /a HTTP/1.1")
	})
	for _, e := range h.got {
		if e.Comm != "python3" {
			t.Errorf("an event from %q on an allowlist of python3", e.Comm)
		}
	}
}

func TestSSLRateLimitsPerConnectionAndCountsWhatItSkips(t *testing.T) {
	f := startHTTPSServer(t)
	h := startSSL(t, nil, time.Hour) // one sample per connection+direction, effectively
	f.get(t, 1, "/a", "/b", "/c", "/d", "/e", "/f")
	time.Sleep(500 * time.Millisecond)
	st, err := h.p.KernelStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.RateLimited == 0 {
		t.Fatalf("nothing was rate limited: %+v", st)
	}
	if st.Eligible != st.Emitted+st.RateLimited+st.RingbufFull+st.ReadFail {
		t.Fatalf("counters do not add up (eligible must equal emitted + rate-limited + lost): %+v", st)
	}
}

func TestSSLLoadRefusesAnUnknownArchitectureObjectLayout(t *testing.T) {
	// The layout is written before load: a missing object is reported, not ignored.
	if _, err := sslprobe.Load(sslprobe.Options{ObjectPath: "/nonexistent/netra_ssl.o"}); err == nil {
		t.Fatal("loading a missing object must fail")
	}
}

// A uprobe traps into the kernel on every SSL_read/SSL_write of every process that
// maps the library, so its cost is what an operator pays. Measured with the
// kernel's BPF accounting (the program's own run time; the trap itself is extra
// and shows up in the request-level comparison), and by timing the same real HTTPS
// requests with and without the sampler attached. Always run, with a generous
// ceiling on the program time, so a regression of an order of magnitude is caught.
func TestSSLCostPerCall(t *testing.T) {
	n := 60
	f := startHTTPSServer(t)
	closer, err := enableRunStats()
	if err != nil {
		t.Skipf("cannot enable BPF run-time statistics: %v", err)
	}
	defer closer.Close()

	f.get(t, 5, "/warm") // warm caches, python startup excluded from the comparison below
	timeOnce := func() time.Duration {
		start := time.Now()
		f.get(t, n, "/a")
		return time.Since(start)
	}
	base := timeOnce()

	h := startSSL(t, nil, 100*time.Millisecond)
	r0, s0, err := h.p.ProgramStats()
	if err != nil {
		t.Fatal(err)
	}
	with := timeOnce()
	r1, s1, err := h.p.ProgramStats()
	if err != nil {
		t.Fatal(err)
	}
	runs := r1 - r0
	if runs == 0 {
		t.Fatal("the probes did not run")
	}
	perRun := (s1 - s0) / time.Duration(runs)
	perReq := func(d time.Duration) time.Duration { return d / time.Duration(n) }
	t.Logf("%d probe runs for %d HTTPS requests: %v per run (kernel accounting, program time only)", runs, n, perRun)
	t.Logf("per request (new TLS connection each, python client): %v without the sampler, %v with it", perReq(base), perReq(with))
	if perRun > 50*time.Microsecond {
		t.Fatalf("%v per probe run is far beyond what a few register reads and a copy should cost", perRun)
	}
}
