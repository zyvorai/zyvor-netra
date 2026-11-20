// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package scandetect

import (
	"context"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func tcpEvent(ts uint64, at time.Time, dstIP string, dstPort uint16, flags uint8) models.FastPathEvent {
	return models.FastPathEvent{
		TimestampNS: ts, ObservedAt: at,
		Protocol: "TCP", Direction: "egress",
		DestinationIP: dstIP, DestinationPort: dstPort, TCPFlags: flags,
		Namespace: "ns", Pod: "p", WorkloadName: "w", Comm: "app",
	}
}

func TestIsTCPEgressAttempt(t *testing.T) {
	base := tcpEvent(1, time.Now(), "10.0.0.1", 80, tcpFlagSYN)
	if !isTCPEgressAttempt(base) {
		t.Fatal("expected a well-formed TCP egress event to match")
	}
	cases := []struct {
		name string
		mod  func(models.FastPathEvent) models.FastPathEvent
	}{
		{"udp", func(e models.FastPathEvent) models.FastPathEvent { e.Protocol = "UDP"; return e }},
		{"ingress", func(e models.FastPathEvent) models.FastPathEvent { e.Direction = "ingress"; return e }},
		{"no destination", func(e models.FastPathEvent) models.FastPathEvent { e.DestinationIP = ""; return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if isTCPEgressAttempt(tc.mod(base)) {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
		})
	}
}

func TestRunDerivesSynOnlyAndResetFromTCPFlags(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDestPorts = 3
	cfg.MinAttempts = 3
	cfg.Window = time.Hour
	d := New(cfg)
	base := time.Now()

	events := []models.FastPathEvent{
		tcpEvent(1, base, "10.0.0.5", 1, tcpFlagSYN), // SYN only
		tcpEvent(2, base.Add(time.Millisecond), "10.0.0.5", 2, tcpFlagSYN),
		tcpEvent(3, base.Add(2*time.Millisecond), "10.0.0.5", 3, tcpFlagSYN|tcpFlagACK), // SYN+ACK: not SYN-only
		tcpEvent(4, base.Add(3*time.Millisecond), "10.0.0.5", 4, tcpFlagRST),
		// A UDP event to the same host/port must never be observed.
		{TimestampNS: 5, ObservedAt: base.Add(4 * time.Millisecond), Protocol: "UDP", Direction: "egress", DestinationIP: "10.0.0.5", DestinationPort: 5},
	}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Events: events}}}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	d.Run(ctx, time.Hour, func() []models.AgentStatus { return agents })

	snap := d.Snapshot()
	if snap.AttemptsSeen != 4 {
		t.Fatalf("AttemptsSeen = %d, want 4 (UDP event must be filtered out)", snap.AttemptsSeen)
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingPortScan {
			found = true
			if f.SYNOnly != 2 {
				t.Errorf("SYNOnly = %d, want 2 (only the pure-SYN events, not SYN+ACK)", f.SYNOnly)
			}
			if f.Resets != 1 {
				t.Errorf("Resets = %d, want 1", f.Resets)
			}
		}
	}
	if !found {
		t.Fatal("expected a port_scan finding fed via Run")
	}
}

func TestRunSkipsStaleAgents(t *testing.T) {
	d := New(DefaultConfig())
	events := []models.FastPathEvent{tcpEvent(1, time.Now(), "10.0.0.1", 80, tcpFlagSYN)}
	agents := []models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", Events: events}}}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	d.Run(ctx, time.Hour, func() []models.AgentStatus { return agents })

	if snap := d.Snapshot(); snap.AttemptsSeen != 0 {
		t.Fatalf("AttemptsSeen = %d, want 0 (stale agent must be skipped)", snap.AttemptsSeen)
	}
}

func TestRunWatermarkPreventsReobservationAcrossTicks(t *testing.T) {
	d := New(DefaultConfig())
	base := time.Now()
	events := []models.FastPathEvent{tcpEvent(1, base, "10.0.0.1", 80, tcpFlagSYN)}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Events: events}}}

	var calls int
	fetch := func() []models.AgentStatus {
		calls++
		return agents
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	d.Run(ctx, 20*time.Millisecond, fetch)

	if calls < 2 {
		t.Fatalf("fetch called %d times, want at least 2 ticks to exercise the watermark", calls)
	}
	if snap := d.Snapshot(); snap.AttemptsSeen != 1 {
		t.Fatalf("AttemptsSeen = %d, want 1 (the same event must not be re-observed on later ticks)", snap.AttemptsSeen)
	}
}
