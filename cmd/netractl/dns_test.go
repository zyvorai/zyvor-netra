// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func dnsFixture() explainEvent {
	return explainEvent{Type: "dns-response", Action: "observed", Protocol: "UDP", Hook: "cgroup", Direction: "ingress", SourcePort: 53, SourceIP: "192.0.2.53", DNSQuery: "api.example.com", DNSRcode: 3, LatencyUS: 1250, ObservedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC), explainIdentity: explainIdentity{Namespace: "prod", Pod: "api", CgroupID: 42}}
}
func TestDNSResponseCodes(t *testing.T) {
	for _, tt := range []struct {
		code        uint8
		name, check string
	}{{0, "NOERROR", "does not prove an answer"}, {1, "FORMERR", "encoding"}, {2, "SERVFAIL", "upstream logs"}, {3, "NXDOMAIN", "search domains"}, {4, "NOTIMP", "supports"}, {5, "REFUSED", "access controls"}, {6, "RCODE_6", "no specific cause"}, {15, "RCODE_15", "no specific cause"}} {
		e := dnsFixture()
		e.DNSRcode = tt.code
		kind, evidence, next := dnsResponseFinding(e)
		expected := "dns-response-error"
		if tt.code == 0 {
			expected = "dns-response"
		}
		if kind != expected || !strings.Contains(evidence, tt.name) || !strings.Contains(next, tt.check) {
			t.Fatal(tt, kind, evidence, next)
		}
	}
}
func TestDNSResponseRequiresNativeEvent(t *testing.T) {
	for _, change := range []func(*explainEvent){func(e *explainEvent) { e.Type = "dns" }, func(e *explainEvent) { e.Action = "blocked" }, func(e *explainEvent) { e.Protocol = "TCP" }, func(e *explainEvent) { e.Hook = "tc" }, func(e *explainEvent) { e.Direction = "egress" }, func(e *explainEvent) { e.SourcePort = 5353 }, func(e *explainEvent) { e.DNSQuery = "" }, func(e *explainEvent) { e.DNSRcode = 16 }} {
		e := dnsFixture()
		change(&e)
		if kind, _, _ := dnsResponseFinding(e); kind != "" {
			t.Fatal("misclassified event", e, kind)
		}
	}
}
func TestDNSResponseScopeAndNoDoubleCounting(t *testing.T) {
	e := dnsFixture()
	a := explainAgent{Node: "n", ObservedAt: e.ObservedAt, Events: []explainEvent{e}}
	for _, args := range [][]string{{"--pod", "prod/api", "--dns", "API.EXAMPLE.COM."}, {"--node", "n"}, {"--all"}} {
		o, err := parseExplain(args)
		if err != nil {
			t.Fatal(err)
		}
		r := buildExplain([]explainAgent{a}, o, e.ObservedAt)
		if r.FindingsTotal != 1 || r.Findings[0].Kind != "dns-response-error" || !strings.Contains(r.Findings[0].Evidence, "NXDOMAIN") {
			t.Fatal(r)
		}
	}
	for _, args := range [][]string{{"--pod", "other/api"}, {"--node", "other"}, {"--dns", "other.example.com"}, {"--destination", "192.0.2.53"}} {
		o, err := parseExplain(args)
		if err != nil {
			t.Fatal(err)
		}
		if r := buildExplain([]explainAgent{a}, o, e.ObservedAt); r.FindingsTotal != 0 {
			t.Fatal("scope leak", args, r)
		}
	}
	o, _ := parseExplain([]string{"--all"})
	a.Stale = true
	if r := buildExplain([]explainAgent{a}, o, e.ObservedAt); r.FindingsTotal != 0 {
		t.Fatal("stale report", r)
	}
}
func TestDNSResponseZeroOmittedAndEscaping(t *testing.T) {
	var e explainEvent
	err := json.Unmarshal([]byte(`{"type":"dns-response","action":"observed","protocol":"UDP","hook":"cgroup","direction":"ingress","sourcePort":53,"dnsQuery":"example.com","latencyUs":25}`), &e)
	if err != nil {
		t.Fatal(err)
	}
	if kind, _, _ := dnsResponseFinding(e); kind != "dns-response" {
		t.Fatal(kind)
	}
	e.DNSQuery = "bad\n\x1b[31m"
	e.SourceIP = "resolver\n"
	_, evidence, _ := dnsResponseFinding(e)
	if strings.ContainsAny(evidence, "\n\x1b") {
		t.Fatal("terminal control characters", evidence)
	}
}
