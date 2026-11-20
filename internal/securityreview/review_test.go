// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package securityreview

import (
	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/scandetect"
	"testing"
	"time"
)

func TestOptimizerDirectionFamilyProtocolAndSYN(t *testing.T) {
	c := models.EBPFFastPathConfig{BlockedIPv4: []string{"192.0.2.5"}, BlockedIngressIPv4: []string{"192.0.2.5"}, BlockedCIDRs: []models.EBPFCIDRRule{{CIDR: "192.0.2.0/24", Direction: "egress"}, {CIDR: "2001:db8::/32", Direction: "egress"}}, SynDropCIDR: []models.EBPFSynDropCIDR{{CIDR: "192.0.2.0/24", Direction: "egress"}}, BlockedPorts: []models.EBPFPortRule{{Port: 443, Protocol: "ANY", Direction: "egress"}, {Port: 443, Protocol: "TCP", Direction: "egress"}, {Port: 443, Protocol: "UDP", Direction: "ingress"}}}
	r := Optimize(c, nil, time.Now())
	if len(r.Suggestions) != 2 {
		t.Fatalf("%+v", r.Suggestions)
	}
	// Exact all-packet deny is not covered by a SYN-restricted /24.
	for _, s := range r.Suggestions {
		if s.Rule == r.Rules[0].ID && s.Kind == "covered" {
			t.Fatal("SYN-only covers full deny")
		}
	}
	if r.AutoApplied {
		t.Fatal("auto-applied")
	}
	before := c.BlockedIPv4[0]
	r.Rules[0].Value = "mutated"
	if c.BlockedIPv4[0] != before {
		t.Fatal("config mutated")
	}
}
func TestMatchingEventsExcludeStaleAndUseDestinationPort(t *testing.T) {
	now := time.Now()
	e := models.FastPathEvent{Direction: "ingress", Hook: "cgroup", Protocol: "TCP", SourcePort: 9999, DestinationPort: 443, ObservedAt: now}
	c := models.EBPFFastPathConfig{BlockedPorts: []models.EBPFPortRule{{Port: 443, Protocol: "TCP", Direction: "ingress"}}}
	events := []models.FastPathEvent{e}
	old := e
	old.ObservedAt = now.Add(-time.Hour)
	events = append(events, old)
	xdp := e
	xdp.Hook = "xdp"
	xdp.DestinationPort = 9999
	xdp.SourcePort = 443
	events = append(events, xdp)
	future := e
	future.ObservedAt = now.Add(time.Second)
	events = append(events, future)
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "n", Events: events}}
	b := a
	b.Stale = true
	r := Optimize(c, []models.AgentStatus{a, b}, now)
	if r.Rules[0].MatchingEvents != 1 {
		t.Fatalf("%+v", r.Rules[0])
	}
}
func TestCorrelateExactFreshDeduplicatedAndDeterministic(t *testing.T) {
	now := time.Now()
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "n", Events: []models.FastPathEvent{{ObservedAt: now, Namespace: "ns", Pod: "p", Direction: "egress", DestinationIP: "192.0.2.1"}}}}
	d := dnsdetect.Finding{ID: "d", Node: "n", Namespace: "ns", Pod: "p", Domain: "example.com", LastSeen: now}
	entries := []intel.Entry{{Type: "ip", Value: "192.0.2.1", Direction: "egress"}}
	r := Correlate([]models.AgentStatus{a}, []dnsdetect.Finding{d, d}, nil, entries, now)
	if len(r.Items) != 1 || len(r.Items[0].Evidence) != 2 {
		t.Fatalf("%+v", r)
	}
	again := Correlate([]models.AgentStatus{a}, []dnsdetect.Finding{d}, nil, entries, now)
	if r.Items[0].ID != again.Items[0].ID || r.Items[0].Evidence[0].ID != again.Items[0].Evidence[0].ID {
		t.Fatal("unstable ids")
	}
	for _, mutate := range []func(){func() { d.Node = "other" }, func() { d.Pod = "other" }, func() { d.Namespace = "other" }, func() { d.LastSeen = now.Add(-time.Hour) }, func() { d.LastSeen = now.Add(time.Hour) }, func() { a.Stale = true }} {
		originalD, originalA := d, a
		mutate()
		if len(Correlate([]models.AgentStatus{a}, []dnsdetect.Finding{d}, nil, entries, now).Items) != 0 {
			t.Fatal("joined unrelated/stale evidence")
		}
		d, a = originalD, originalA
	}
	if len(Correlate([]models.AgentStatus{a}, nil, []scandetect.Finding{{Node: "n", Namespace: "ns", Pod: "p", LastSeen: now}}, nil, now).Items) != 0 {
		t.Fatal("single signal incident")
	}
}
func TestIncidentCapKeepsIndependentKinds(t *testing.T) {
	now := time.Now()
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "n"}}
	dns := []dnsdetect.Finding{}
	for i := 0; i < 70; i++ {
		dns = append(dns, dnsdetect.Finding{Node: "n", Namespace: "ns", Pod: "p", Domain: time.Duration(i).String(), LastSeen: now})
	}
	scan := []scandetect.Finding{{Node: "n", Namespace: "ns", Pod: "p", LastSeen: now.Add(-time.Minute)}}
	r := Correlate([]models.AgentStatus{a}, dns, scan, nil, now)
	kinds := map[string]bool{}
	for _, e := range r.Items[0].Evidence {
		kinds[e.Kind] = true
	}
	if !r.Truncated || len(r.Items[0].Evidence) != 50 || len(kinds) != 2 {
		t.Fatal("truncation discarded independent signal")
	}
}
