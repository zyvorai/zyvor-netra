// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDenysetPlanIsReadOnlyAndSendsNoReceiptHeader(t *testing.T) {
	var hdr, tok string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr, tok = r.Header.Get("X-Netra-No-Receipt"), r.Header.Get("X-Netra-Plan-Token")
		_, _ = w.Write([]byte(`{"planHash":"h"}`))
	}))
	defer ts.Close()
	c := testClient(t, ts)
	// Registered and callable with mutations disabled.
	if res := callTool(t, c, false, "netra_denyset_plan", map[string]any{"file": "netra-denyset/1"}); res.IsError {
		t.Fatalf("%+v", res)
	}
	if hdr != "1" || tok != "" {
		t.Fatalf("hdr=%q tok=%q", hdr, tok)
	}
	for _, n := range []string{"netra_deny_leases", "netra_deny_lease_history", "netra_deny_lease_rails"} {
		if res := callTool(t, c, false, n, map[string]any{}); res.IsError {
			t.Fatalf("%s: %+v", n, res)
		}
	}
}

func TestDenysetApplyOnlyWithMutations(t *testing.T) {
	var gotTok, gotRisk string
	var body map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTok, gotRisk = r.Header.Get("X-Netra-Plan-Token"), r.Header.Get("X-Netra-Confirm-Risk")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = w.Write([]byte(`{"added":1}`))
	}))
	defer ts.Close()
	c := testClient(t, ts)
	args := map[string]any{"file": "f", "plan_hash": "h", "plan_token": "tok", "confirm_risk": "high", "break_glass": "incident 4711 ok"}
	ro, err := buildServer(c, false)
	if err != nil {
		t.Fatal(err)
	}
	names := toolNames(t, ro)
	for _, n := range []string{"netra_denyset_apply", "netra_denyset_plan_receipt"} {
		if contains(names, n) {
			t.Fatalf("%s must not exist without NETRA_MCP_ALLOW_MUTATIONS", n)
		}
	}
	for _, n := range []string{"netra_denyset_plan", "netra_deny_leases", "netra_deny_lease_history", "netra_deny_lease_rails"} {
		if !contains(names, n) {
			t.Fatalf("%s missing from the read-only tool set", n)
		}
	}
	if res := callTool(t, c, true, "netra_denyset_apply", args); res.IsError {
		t.Fatalf("%+v", res)
	}
	if gotTok != "tok" || gotRisk != "high" || body["planHash"] != "h" || body["breakGlass"] != "incident 4711 ok" {
		t.Fatalf("%q %q %v", gotTok, gotRisk, body)
	}
}
