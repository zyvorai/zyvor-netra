// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package sslprobe

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/zyvorai/netra/internal/l7sample"
)

func buildEvent(write bool, pid, tid uint32, comm string, payload []byte) []byte {
	b := make([]byte, EventSize)
	binary.LittleEndian.PutUint64(b[0:], 42)
	binary.LittleEndian.PutUint64(b[8:], uint64(pid)<<32|uint64(tid))
	binary.LittleEndian.PutUint64(b[16:], 4242)
	binary.LittleEndian.PutUint64(b[24:], 0xdeadbeef)
	if !write {
		b[32] = 1
	}
	binary.LittleEndian.PutUint16(b[36:], uint16(len(payload)))
	copy(b[40:56], comm)
	copy(b[headerLen:], payload)
	return b
}

func TestLayoutSizesMatchTheCStructs(t *testing.T) {
	// struct ssl_layout: 5 x u16 + 2 x u8 = 12; struct ssl_event packed = 56 + 128.
	if got := unsafe.Sizeof(Layout{}); got != 12 {
		t.Fatalf("Layout is %d bytes, the C struct is 12", got)
	}
	if headerLen != 8+8+8+8+1+3+2+2+16 || EventSize != 184 {
		t.Fatalf("headerLen=%d EventSize=%d out of step with bpf/netra_ssl.c", headerLen, EventSize)
	}
}

func TestLayoutForKnownArchitecturesAndRefusesOthers(t *testing.T) {
	amd, err := LayoutFor("amd64")
	if err != nil || amd.Arg1 != 112 || amd.Arg2 != 104 || amd.Arg3 != 96 || amd.Arg4 != 88 || amd.Ret != 80 || amd.Valid != 1 {
		t.Fatalf("amd64 = %+v, %v", amd, err)
	}
	arm, err := LayoutFor("arm64")
	if err != nil || arm.Arg1 != 0 || arm.Arg2 != 8 || arm.Arg3 != 16 || arm.Arg4 != 24 || arm.Ret != 0 || arm.Valid != 1 {
		t.Fatalf("arm64 = %+v, %v", arm, err)
	}
	for _, a := range []string{"386", "riscv64", "ppc64le", ""} {
		if l, err := LayoutFor(a); err == nil || l.Valid != 0 {
			t.Errorf("%q must be refused, got %+v", a, l)
		}
	}
}

func TestDecodeEvent(t *testing.T) {
	e, err := DecodeEvent(buildEvent(true, 1234, 1240, "curl", []byte("GET / HTTP/1.1\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Write || e.PID != 1234 || e.TID != 1240 || e.Comm != "curl" || e.CgroupID != 4242 || e.SSL != 0xdeadbeef || string(e.Data) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("event = %+v", e)
	}
	r, err := DecodeEvent(buildEvent(false, 1, 2, "", []byte("x")))
	if err != nil || r.Write || r.Comm != "" {
		t.Fatalf("read event = %+v, %v", r, err)
	}
	full := make([]byte, EventSize)
	copy(full[40:], "0123456789abcdef") // a comm with no NUL terminator must not run off the end
	binary.LittleEndian.PutUint16(full[36:], 1)
	if e, err := DecodeEvent(full); err != nil || len(e.Comm) != 16 {
		t.Fatalf("unterminated comm: %+v %v", e, err)
	}
}

func TestDecodeEventRejectsMalformedRecords(t *testing.T) {
	good := buildEvent(true, 1, 1, "x", []byte("y"))
	if _, err := DecodeEvent(good[:EventSize-1]); err == nil {
		t.Error("short record accepted")
	}
	for name, mutate := range map[string]func([]byte){
		"zero length": func(b []byte) { binary.LittleEndian.PutUint16(b[36:], 0) },
		"huge length": func(b []byte) { binary.LittleEndian.PutUint16(b[36:], CopyMax+1) },
	} {
		b := append([]byte(nil), good...)
		mutate(b)
		if _, err := DecodeEvent(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestClassifyInfersTheRoleFromWhatTheProcessWroteOrRead(t *testing.T) {
	req := []byte("GET /orders/42?token=SECRET HTTP/1.1\r\nHost: shop.example\r\nCookie: s=SECRET\r\n\r\n")
	resp := []byte("HTTP/1.1 503 Service Unavailable\r\n\r\n")
	for name, c := range map[string]struct {
		write bool
		data  []byte
		kind  l7sample.Kind
		role  string
	}{
		"client writes a request":  {true, req, l7sample.KindRequest, l7sample.RoleIssued},
		"client reads a response":  {false, resp, l7sample.KindResponse, l7sample.RoleIssued},
		"server reads a request":   {false, req, l7sample.KindRequest, l7sample.RoleServed},
		"server writes a response": {true, resp, l7sample.KindResponse, l7sample.RoleServed},
	} {
		o, role, ok := Classify(c.write, c.data)
		if !ok || o.Kind != c.kind || role != c.role {
			t.Errorf("%s => %+v role=%s ok=%v, want %v/%s", name, o, role, ok, c.kind, c.role)
		}
	}
	// The path, query string and cookie never reach the result.
	o, _, _ := Classify(true, req)
	if o.Op != "GET" || o.Host != "shop.example" {
		t.Fatalf("obs = %+v", o)
	}
	if s := fmt.Sprintf("%+v", o); containsAny(s, "SECRET", "orders", "token") {
		t.Fatalf("result carries request text: %s", s)
	}
	for _, junk := range [][]byte{[]byte("\x16\x03\x01\x00\xa5"), []byte("binary \x00\x01 bytes"), []byte("*1\r\n$4\r\nPING\r\n")} {
		if _, _, ok := Classify(true, junk); ok {
			t.Errorf("%q was classified as HTTP", junk)
		}
	}
}

func TestClassifyRecognisesHTTP2Preface(t *testing.T) {
	o, role, ok := Classify(true, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if !ok || o.Proto != l7sample.ProtoHTTP2 || o.Op != "connection" || role != l7sample.RoleIssued {
		t.Fatalf("h2 preface = %+v role=%s ok=%v", o, role, ok)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}

func writeMaps(t *testing.T, root string, pid int, lines ...string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverFindsEachDistinctLibraryOnceAcrossProcesses(t *testing.T) {
	root := t.TempDir()
	// Two processes share one file (same dev:inode): attach it once. A third, in a
	// container, maps a different file.
	writeMaps(t, root, 100,
		"7f0000000000-7f0000100000 r-xp 00000000 fd:01 1234567 /usr/lib/x86_64-linux-gnu/libssl.so.3",
		"7f0000200000-7f0000300000 r-xp 00000000 fd:01 7654321 /usr/lib/x86_64-linux-gnu/libcrypto.so.3")
	writeMaps(t, root, 200,
		"7f1111000000-7f1111100000 r--p 00000000 fd:01 1234567 /usr/lib/x86_64-linux-gnu/libssl.so.3")
	writeMaps(t, root, 300,
		"7f2222000000-7f2222100000 r-xp 00000000 00:2a 99 /usr/lib/libssl.so.1.1")
	got := Discover(root)
	if len(got) != 2 {
		t.Fatalf("libs = %+v, want 2 distinct files", got)
	}
	byKey := map[string]Lib{}
	for _, l := range got {
		byKey[l.Key] = l
	}
	a := byKey["fd:01:1234567"]
	if a.PID != 100 || a.Path != filepath.Join(root, "100", "root", "/usr/lib/x86_64-linux-gnu/libssl.so.3") {
		t.Fatalf("shared lib = %+v, want it reached through the first process", a)
	}
	if b := byKey["00:2a:99"]; b.PID != 300 || b.MapsPath != "/usr/lib/libssl.so.1.1" {
		t.Fatalf("container lib = %+v", b)
	}
}

func TestDiscoverIgnoresWhatIsNotLibsslAndUnusableMappings(t *testing.T) {
	root := t.TempDir()
	writeMaps(t, root, 1,
		"7f00-7f01 r-xp 00000000 fd:01 10 /usr/lib/libsslcrypto.so",       // lookalike
		"7f00-7f01 r-xp 00000000 fd:01 11 /usr/lib/libssl_extras.so.1",    // lookalike
		"7f00-7f01 r-xp 00000000 fd:01 12 /usr/lib/libssl.so.3 (deleted)", // replaced on disk
		"7f00-7f01 r-xp 00000000 00:00 0 /usr/lib/libssl.so.3",            // inode 0: anonymous
		"7f00-7f01 r-xp 00000000 fd:01 13",                                // no path
		"7f00-7f01 r-xp 00000000 fd:01 14 /usr/lib/libssl.so")             // this one counts
	if err := os.MkdirAll(filepath.Join(root, "notapid"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "555"), 0o755); err != nil { // no maps file: a process that exited
		t.Fatal(err)
	}
	got := Discover(root)
	if len(got) != 1 || got[0].Key != "fd:01:14" {
		t.Fatalf("libs = %+v, want only libssl.so", got)
	}
	if got := Discover(filepath.Join(root, "missing")); got != nil {
		t.Fatalf("a missing proc root should find nothing, got %+v", got)
	}
}
