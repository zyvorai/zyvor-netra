// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dnsdetect

import (
	"context"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func dnsResponseEvent(ts uint64, at time.Time, name string, rcode uint8) models.FastPathEvent {
	return models.FastPathEvent{
		TimestampNS: ts, ObservedAt: at,
		Type: "dns-response", Action: "observed", Protocol: "UDP", Hook: "cgroup",
		Direction: "ingress", SourcePort: 53,
		DNSQuery: name, DNSRcode: rcode,
		Namespace: "ns", Pod: "p", WorkloadName: "w", Comm: "app",
	}
}

func TestIsDNSResponseMatchesOnlyTheResponseLeg(t *testing.T) {
	base := dnsResponseEvent(1, time.Now(), "example.com", 0)
	if !isDNSResponse(base) {
		t.Fatal("expected a well-formed dns-response event to match")
	}

	cases := []struct {
		name string
		mod  func(models.FastPathEvent) models.FastPathEvent
	}{
		{"query leg", func(e models.FastPathEvent) models.FastPathEvent {
			e.Type = "dns"
			e.Direction = "egress"
			e.SourcePort = 0
			return e
		}},
		{"wrong type", func(e models.FastPathEvent) models.FastPathEvent { e.Type = "other"; return e }},
		{"not observed", func(e models.FastPathEvent) models.FastPathEvent { e.Action = "blocked"; return e }},
		{"tcp not udp", func(e models.FastPathEvent) models.FastPathEvent { e.Protocol = "TCP"; return e }},
		{"wrong hook", func(e models.FastPathEvent) models.FastPathEvent { e.Hook = "tc"; return e }},
		{"egress not ingress", func(e models.FastPathEvent) models.FastPathEvent { e.Direction = "egress"; return e }},
		{"wrong source port", func(e models.FastPathEvent) models.FastPathEvent { e.SourcePort = 5353; return e }},
		{"empty query", func(e models.FastPathEvent) models.FastPathEvent { e.DNSQuery = ""; return e }},
		{"rcode out of range", func(e models.FastPathEvent) models.FastPathEvent { e.DNSRcode = 16; return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if isDNSResponse(tc.mod(base)) {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
		})
	}
}

func TestRunFeedsMatchedEventsIntoObserve(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NXDomainMinCount = 3
	cfg.NXDomainRatio = 0.5
	d := New(cfg)
	base := time.Now()

	events := []models.FastPathEvent{
		dnsResponseEvent(1, base, "flaky.example.com", RCodeNXDomain),
		dnsResponseEvent(2, base.Add(time.Second), "flaky.example.com", RCodeNXDomain),
		dnsResponseEvent(3, base.Add(2*time.Second), "flaky.example.com", RCodeNXDomain),
		// A query-leg event for the same name must not be double-counted.
		{TimestampNS: 4, ObservedAt: base.Add(3 * time.Second), Type: "dns", Direction: "egress", DNSQuery: "flaky.example.com"},
	}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Events: events}}}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	d.Run(ctx, time.Hour, func() []models.AgentStatus { return agents })

	snap := d.Snapshot()
	if snap.QueriesSeen != 3 {
		t.Fatalf("QueriesSeen = %d, want 3 (query-leg event must be filtered out)", snap.QueriesSeen)
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingNXDomainStorm {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an nxdomain_storm finding fed via Run")
	}
}

func TestRunSkipsStaleAgents(t *testing.T) {
	d := New(DefaultConfig())
	events := []models.FastPathEvent{dnsResponseEvent(1, time.Now(), "example.com", 0)}
	agents := []models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", Events: events}}}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	d.Run(ctx, time.Hour, func() []models.AgentStatus { return agents })

	if snap := d.Snapshot(); snap.QueriesSeen != 0 {
		t.Fatalf("QueriesSeen = %d, want 0 (stale agent must be skipped)", snap.QueriesSeen)
	}
}

func TestRunWatermarkPreventsReobservationAcrossTicks(t *testing.T) {
	d := New(DefaultConfig())
	base := time.Now()
	events := []models.FastPathEvent{dnsResponseEvent(1, base, "example.com", 0)}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Events: events}}}

	var calls int
	fetch := func() []models.AgentStatus {
		calls++
		return agents // same ring buffer contents returned on every tick
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	d.Run(ctx, 20*time.Millisecond, fetch)

	if calls < 2 {
		t.Fatalf("fetch called %d times, want at least 2 ticks to exercise the watermark", calls)
	}
	if snap := d.Snapshot(); snap.QueriesSeen != 1 {
		t.Fatalf("QueriesSeen = %d, want 1 (the same event must not be re-observed on later ticks)", snap.QueriesSeen)
	}
}

func TestRunQTypeActivatesTXTSignal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxUniqueSubdomains = 3
	cfg.MinAvgLabelLen = 0
	cfg.MinEntropy = 0
	d := New(cfg)
	now := time.Now()
	events := []models.FastPathEvent{}
	for i, name := range []string{"one.example.com", "two.example.com", "three.example.com"} {
		e := dnsResponseEvent(uint64(i+1), now, name, 0)
		e.DNSQType = QTypeTXT
		events = append(events, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.Run(ctx, time.Hour, func() []models.AgentStatus {
		cancel()
		return []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n", Events: events}}}
	})
	for _, f := range d.Findings() {
		for _, signal := range f.Signals {
			if signal == "txt-heavy" {
				return
			}
		}
	}
	t.Fatal("TXT QTYPE did not reach detector")
}
