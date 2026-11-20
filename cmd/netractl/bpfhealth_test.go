// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBPFMapsMissingExplainFromAgentJSON(t *testing.T) {
	var a explainAgent
	err := json.Unmarshal([]byte(`{"node":"n","observedAt":"2026-09-13T00:00:00Z","missingMaps":["allowed_ports","rate_v6"]}`), &a)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := parseExplain([]string{"--node", "n"})
	r := buildExplain([]explainAgent{a}, o, a.ObservedAt)
	if r.FindingsTotal != 1 || r.Findings[0].Kind != "bpf-maps-missing" || !strings.Contains(r.Findings[0].Evidence, "allowed_ports") || !strings.Contains(r.Findings[0].Evidence, "rate_v6") {
		t.Fatal(r)
	}
	for _, args := range [][]string{{"--node", "other"}, {"--pod", "ns/p"}, {"--namespace", "ns"}, {"--node", "n", "--pid", "1"}, {"--container", "full"}, {"--destination", "192.0.2.1"}, {"--dns", "example.com"}, {"--node", "n", "--docker", "app"}} {
		scope, e := parseExplain(args)
		if e != nil {
			t.Fatal(args, e)
		}
		if got := buildExplain([]explainAgent{a}, scope, a.ObservedAt); got.FindingsTotal != 0 {
			t.Fatalf("misattribution %v: %+v", args, got)
		}
	}
	if r := buildExplain([]explainAgent{a}, o, a.ObservedAt.Add(time.Hour)); r.FindingsTotal != 0 {
		t.Fatal("stale evidence", r)
	}
}

func TestBPFMapsMissingFinding(t *testing.T) {
	if kind, _, _ := bpfMapsMissingFinding(nil); kind != "" {
		t.Fatal("empty should not fire", kind)
	}
	kind, evidence, next := bpfMapsMissingFinding([]string{"icmp_errors"})
	if kind != "bpf-maps-missing" || !strings.Contains(evidence, "icmp_errors") || !strings.Contains(next, "Rebuild") {
		t.Fatalf("kind=%q evidence=%q next=%q", kind, evidence, next)
	}
}

func TestRateDropExplainFromAgentJSON(t *testing.T) {
	var a explainAgent
	err := json.Unmarshal([]byte(`{"node":"n","observedAt":"2026-09-13T00:00:00Z","rateDrops":[{"name":"203.0.113.5","count":42}]}`), &a)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := parseExplain([]string{"--node", "n"})
	r := buildExplain([]explainAgent{a}, o, a.ObservedAt)
	if r.FindingsTotal != 1 || r.Findings[0].Kind != "rate-drop" || !strings.Contains(r.Findings[0].Evidence, "203.0.113.5") || !strings.Contains(r.Findings[0].Evidence, "42") {
		t.Fatal(r)
	}
	// Destination scope is compatible with rate-drop (unlike ICMP/bpf-maps-missing).
	dst, e := parseExplain([]string{"--destination", "203.0.113.5"})
	if e != nil {
		t.Fatal(e)
	}
	if got := buildExplain([]explainAgent{a}, dst, a.ObservedAt); got.FindingsTotal != 1 {
		t.Fatalf("destination scope should match: %+v", got)
	}
	other, e := parseExplain([]string{"--destination", "198.51.100.9"})
	if e != nil {
		t.Fatal(e)
	}
	if got := buildExplain([]explainAgent{a}, other, a.ObservedAt); got.FindingsTotal != 0 {
		t.Fatalf("mismatched destination should not match: %+v", got)
	}
	for _, args := range [][]string{{"--node", "other"}, {"--pod", "ns/p"}, {"--namespace", "ns"}, {"--node", "n", "--pid", "1"}, {"--container", "full"}, {"--dns", "example.com"}, {"--node", "n", "--docker", "app"}} {
		scope, e := parseExplain(args)
		if e != nil {
			t.Fatal(args, e)
		}
		if got := buildExplain([]explainAgent{a}, scope, a.ObservedAt); got.FindingsTotal != 0 {
			t.Fatalf("misattribution %v: %+v", args, got)
		}
	}
}

func TestRateDropFinding(t *testing.T) {
	if kind, _, _ := rateDropFinding(explainNamedCount{Name: "203.0.113.5", Count: 0}); kind != "" {
		t.Fatal("zero count should not fire", kind)
	}
	kind, evidence, next := rateDropFinding(explainNamedCount{Name: "203.0.113.5", Count: 42})
	if kind != "rate-drop" || !strings.Contains(evidence, "203.0.113.5") || !strings.Contains(evidence, "42") || !strings.Contains(next, "PPS ceiling") {
		t.Fatalf("kind=%q evidence=%q next=%q", kind, evidence, next)
	}
}
