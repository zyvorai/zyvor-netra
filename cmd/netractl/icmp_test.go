// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestICMPExplainFromAgentJSON(t *testing.T) {
	var a explainAgent
	err := json.Unmarshal([]byte(`{"node":"n","observedAt":"2026-09-13T00:00:00Z","icmpErrors":[{"interfaceIndex":2,"family":"IPv6","type":2,"code":0,"direction":"ingress","hook":"tc","packets":4,"advertisedMtu":1280}]}`), &a)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := parseExplain([]string{"--node", "n"})
	r := buildExplain([]explainAgent{a}, o, a.ObservedAt)
	if r.FindingsTotal != 1 || r.Findings[0].Kind != "icmp-pmtu" || !strings.Contains(r.Findings[0].Evidence, "last-advertised-mtu=1280") {
		t.Fatal(r)
	}
	if !strings.Contains(r.Findings[0].NextCheck, "peer claim") {
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
		t.Fatal("stale ICMP evidence", r)
	}
}
func TestICMPKinds(t *testing.T) {
	for _, tt := range []struct {
		family    string
		typ, code uint8
		kind      string
	}{
		{"IPv4", 3, 4, "icmp-pmtu"}, {"IPv4", 3, 3, "icmp-unreachable"}, {"IPv6", 1, 4, "icmp-unreachable"},
		{"IPv4", 11, 0, "icmp-time-exceeded"}, {"IPv6", 3, 1, "icmp-time-exceeded"},
		{"IPv4", 12, 0, "icmp-parameter-problem"}, {"IPv6", 4, 0, "icmp-parameter-problem"},
		{"IPv4", 8, 0, ""}, {"IPv6", 128, 0, ""}, {"IPv6", 2, 1, ""}, {"unknown", 3, 0, ""},
	} {
		e := explainICMP{Family: tt.family, Type: tt.typ, Code: tt.code, Hook: "tc", Packets: 1}
		kind, _, _ := icmpFinding(e)
		if kind != tt.kind {
			t.Fatal(tt, kind)
		}
		e.Packets = 0
		if kind, _, _ := icmpFinding(e); kind != "" {
			t.Fatal("zero count", kind)
		}
		e.Packets = 1
		e.Hook = "cgroup"
		if kind, _, _ := icmpFinding(e); kind != "" {
			t.Fatal("wrong hook", kind)
		}
	}
}

func TestICMPInterfaceNameEscaping(t *testing.T) {
	e := explainICMP{InterfaceName: "eth0\n\x1b[31m", InterfaceIndex: 2, Family: "IPv4", Type: 3, Code: 4, Hook: "tc", Packets: 1}
	_, evidence, _ := icmpFinding(e)
	if !strings.Contains(evidence, "interface-name=") || !strings.Contains(evidence, "interface-index=2") || strings.ContainsAny(evidence, "\n\x1b") {
		t.Fatal(evidence)
	}
}
