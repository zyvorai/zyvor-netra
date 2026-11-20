// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNetpolQuarantineRequiresSelector(t *testing.T) {
	if err := netpolQuarantine(nil); err == nil {
		t.Fatal("expected an error with no flags")
	}
	if err := netpolQuarantine([]string{"--allow-peer", "10.96.0.10:53/UDP"}); err == nil {
		t.Fatal("expected an error with no selector flags")
	}
}

func TestNetpolQuarantineComposesCallsWithLowRisk(t *testing.T) {
	var v2Enabled, ruleAdded, planned, applied bool
	var ruleBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/ebpf/netpol/v2/config":
			v2Enabled = true
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/v1/ebpf/netpol/rules":
			ruleAdded = true
			_ = json.NewDecoder(r.Body).Decode(&ruleBody)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/v1/ebpf/netpol/default-deny/plan":
			planned = true
			_, _ = w.Write([]byte(`{"risk":"low","matchedWorkloads":1,"workloadsWithAllowRule":1,"receipt":{"token":"receipt-q"}}`))
		case "/api/v1/ebpf/netpol/default-deny":
			applied = true
			if r.Header.Get("X-Netra-Plan-Token") != "receipt-q" {
				t.Fatalf("missing plan token: %#v", r.Header)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	err := netpolQuarantine([]string{"--namespace", "prod", "--pod", "api", "--allow-peer", "10.96.0.10:53/UDP", "--lease", "10m"})
	if err != nil {
		t.Fatal(err)
	}
	if !v2Enabled || !ruleAdded || !planned || !applied {
		t.Fatalf("expected all 4 calls: v2=%v rule=%v plan=%v apply=%v", v2Enabled, ruleAdded, planned, applied)
	}
	if ruleBody["peerIpv4"] != "10.96.0.10" || ruleBody["port"] != float64(53) || ruleBody["protocol"] != "UDP" || ruleBody["action"] != "allow" || ruleBody["direction"] != "egress" {
		t.Fatalf("unexpected rule body: %#v", ruleBody)
	}
}

func TestNetpolQuarantineRequiresConfirmRiskWhenCritical(t *testing.T) {
	var applyCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/ebpf/netpol/v2/config", "/api/v1/ebpf/netpol/rules":
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/v1/ebpf/netpol/default-deny/plan":
			_, _ = w.Write([]byte(`{"risk":"critical","matchedWorkloads":3,"workloadsWithAllowRule":0,"receipt":{"token":"receipt-crit"}}`))
		case "/api/v1/ebpf/netpol/default-deny":
			applyCalls++
			if r.Header.Get("X-Netra-Confirm-Risk") != "critical" {
				t.Fatalf("missing risk confirmation header")
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	if err := netpolQuarantine([]string{"--namespace", "prod"}); err == nil {
		t.Fatal("expected an error without --confirm-risk")
	}
	if applyCalls != 0 {
		t.Fatalf("default-deny should not apply without confirmation, got %d calls", applyCalls)
	}
	if err := netpolQuarantine([]string{"--namespace", "prod", "--confirm-risk", "critical"}); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatalf("expected one confirmed apply, got %d", applyCalls)
	}
}

func TestNetpolQuarantineBarePeerDefaultsToAnyPort(t *testing.T) {
	var ruleBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/ebpf/netpol/rules":
			_ = json.NewDecoder(r.Body).Decode(&ruleBody)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/v1/ebpf/netpol/default-deny/plan":
			_, _ = w.Write([]byte(`{"risk":"low","receipt":{"token":"t"}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	if err := netpolQuarantine([]string{"--pod", "api", "--namespace", "prod", "--allow-peer", "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	if ruleBody["peerIpv4"] != "10.0.0.5" || ruleBody["protocol"] != "ANY" {
		t.Fatalf("unexpected rule body: %#v", ruleBody)
	}
	if _, hasPort := ruleBody["port"]; hasPort {
		t.Fatalf("bare peer should not set a port: %#v", ruleBody)
	}
}
