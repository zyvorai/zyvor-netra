// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDenyset(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "set.denyset")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodSet = "netra-denyset/1\nname: inc\nlease: 10m\ndeny cidr 203.0.113.0/24 egress\n"

func TestDenysetValidateLocal(t *testing.T) {
	if err := run([]string{"denyset", "validate", writeDenyset(t, goodSet)}); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"denyset", "validate", writeDenyset(t, "netra-denyset/1\nname: a\nlease: 5m\ndeny cidr bad egress\n")})
	if err == nil || !strings.Contains(err.Error(), "1 validation") {
		t.Fatalf("%v", err)
	}
	if err := run([]string{"denyset", "validate", filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing file accepted")
	}
	big := writeDenyset(t, goodSet+strings.Repeat("# pad\n", 20000))
	if err := run([]string{"denyset", "validate", big}); err == nil {
		t.Fatal("oversize file accepted")
	}
}

func TestDenysetApplyFlowHeaders(t *testing.T) {
	var applyHdr http.Header
	var applyBody map[string]string
	hash := "h1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/v1/ebpf/denysets/plan":
			_, _ = w.Write([]byte(`{"name":"inc","planHash":"` + hash + `","risk":"high","summary":{"add":1},"items":[{"action":"add","summary":"egress · 203.0.113.0/24","leaseSeconds":600}],"rails":{"trips":[]},"applicable":true,"receipt":{"token":"tok-1"}}`))
		case "/api/v1/ebpf/denysets/apply":
			applyHdr = r.Header.Clone()
			_ = json.Unmarshal(b, &applyBody)
			_, _ = w.Write([]byte(`{"added":1}`))
		default:
			t.Errorf("unexpected %s", r.URL)
		}
	}))
	defer srv.Close()
	useTestServer(t, srv.URL)
	f := writeDenyset(t, goodSet)
	if err := run([]string{"denyset", "plan", f}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"denyset", "apply", f}); err == nil || !strings.Contains(err.Error(), "--plan-hash") {
		t.Fatalf("apply without hash: %v", err)
	}
	if err := run([]string{"denyset", "apply", f, "--plan-hash", hash}); err == nil || !strings.Contains(err.Error(), "--confirm-risk high") {
		t.Fatalf("apply without risk confirm: %v", err)
	}
	if err := run([]string{"denyset", "apply", f, "--plan-hash", "stale", "--confirm-risk", "high"}); err == nil || !strings.Contains(err.Error(), "plan hash changed") {
		t.Fatalf("stale hash: %v", err)
	}
	if applyHdr != nil {
		t.Fatal("apply reached the server despite a refused guard")
	}
	if err := run([]string{"denyset", "apply", f, "--plan-hash", hash, "--confirm-risk", "high", "--break-glass", "incident 4711 ok"}); err != nil {
		t.Fatal(err)
	}
	if applyHdr.Get("X-Netra-Plan-Token") != "tok-1" || applyHdr.Get("X-Netra-Confirm-Risk") != "high" || applyBody["planHash"] != hash || applyBody["breakGlass"] != "incident 4711 ok" {
		t.Fatalf("%v %v", applyHdr, applyBody)
	}
}

func TestDenysetHTTPErrorPrintsLinesAndRails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"error":"x","code":"lease_rail_catch_all","trips":[{"code":"lease_rail_catch_all","message":"needs break-glass"}],"breakGlassRequired":true,"errors":[{"line":4,"message":"bad"}]}`))
	}))
	defer srv.Close()
	useTestServer(t, srv.URL)
	err := run([]string{"denyset", "plan", writeDenyset(t, goodSet)})
	if err == nil || !strings.Contains(err.Error(), "lease_rail_catch_all") || !strings.Contains(err.Error(), "--break-glass") {
		t.Fatalf("%v", err)
	}
}

func TestDenysetBadUsage(t *testing.T) {
	for _, a := range [][]string{{"denyset"}, {"denyset", "bogus"}, {"denyset", "plan"}, {"denyset", "plan", "f", "--nope"}, {"denyset", "leases", "--within"}, {"denyset", "leases", "x"}} {
		if err := run(a); err == nil {
			t.Fatalf("%v accepted", a)
		}
	}
}
