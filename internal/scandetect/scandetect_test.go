// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package scandetect

import (
	"strconv"
	"testing"
	"time"
)

func TestPortScan(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDestPorts = 20
	cfg.MinAttempts = 10
	cfg.Window = 5 * time.Minute
	d := New(cfg)

	base := time.Now()
	// 30 ports to a single IP from one pod.
	for i := 0; i < 30; i++ {
		d.Observe(Event{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Namespace: "default", Pod: "scanner-1", Workload: "scanner",
			DstIP:   "10.0.0.5",
			DstPort: uint16(1 + i),
			SynOnly: true,
		})
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingPortScan && f.Pod == "scanner-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected port_scan, got %+v", d.Findings())
	}
}

func TestFanOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDestIPs = 20
	cfg.MinAttempts = 10
	cfg.Window = 5 * time.Minute
	d := New(cfg)

	base := time.Now()
	for i := 0; i < 40; i++ {
		d.Observe(Event{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Namespace: "default", Pod: "fan-1",
			DstIP:   "10.0.0." + strconv.Itoa(1+i),
			DstPort: 443,
		})
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingFanOut {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected fan_out, got %+v", d.Findings())
	}
}

func TestLateralMovement(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDestIPs = 10
	cfg.MaxDestPorts = 10
	cfg.MinAttempts = 10
	cfg.Window = 5 * time.Minute
	d := New(cfg)

	base := time.Now()
	n := 0
	for i := 0; i < 20; i++ {
		for p := 0; p < 20; p++ {
			d.Observe(Event{
				Timestamp: base.Add(time.Duration(n) * time.Millisecond),
				Namespace: "default", Pod: "worm-1",
				DstIP:   "10.0.0." + strconv.Itoa(i+1),
				DstPort: uint16(p + 1),
			})
			n++
		}
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingLateral {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected lateral_movement, got %+v", d.Findings())
	}
}

func TestSYNFlood(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinAttempts = 10
	cfg.Window = 5 * time.Minute
	d := New(cfg)

	base := time.Now()
	for i := 0; i < 100; i++ {
		d.Observe(Event{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Namespace: "default", Pod: "flood-1",
			DstIP:   "10.0.0.1",
			DstPort: 80,
			SynOnly: true,
		})
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingSYNFlood {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected syn_flood, got %+v", d.Findings())
	}
}

func TestWindowReset(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Window = 1 * time.Second
	d := New(cfg)
	base := time.Now()
	d.Observe(Event{Timestamp: base, Namespace: "ns", Pod: "p", DstIP: "10.0.0.1", DstPort: 80})
	d.Observe(Event{Timestamp: base.Add(5 * time.Second), Namespace: "ns", Pod: "p", DstIP: "10.0.0.2", DstPort: 80})
	d.mu.Lock()
	st := d.states[workloadKey{namespace: "ns", pod: "p"}]
	d.mu.Unlock()
	if st == nil {
		t.Fatal("state missing")
	}
	if st.attempts != 1 {
		t.Errorf("window did not reset: attempts=%d", st.attempts)
	}
	if _, ok := st.dstIPs["10.0.0.1"]; ok {
		t.Error("old dst IP survived window reset")
	}
}

func TestBenignTrafficNoFinding(t *testing.T) {
	cfg := DefaultConfig()
	d := New(cfg)
	base := time.Now()
	// One pod talking to one destination, many times.
	for i := 0; i < 200; i++ {
		d.Observe(Event{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Namespace: "ns", Pod: "web-1",
			DstIP: "10.0.0.10", DstPort: 443,
		})
	}
	if got := len(d.Findings()); got != 0 {
		t.Fatalf("benign traffic produced %d findings: %+v", got, d.Findings())
	}
}

func TestFindingsTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FindingsTTL = 50 * time.Millisecond
	cfg.MinAttempts = 5
	cfg.MaxDestPorts = 3
	d := New(cfg)
	base := time.Now()
	for i := 0; i < 10; i++ {
		d.Observe(Event{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Namespace: "ns", Pod: "p",
			DstIP: "10.0.0.5", DstPort: uint16(i + 1), SynOnly: true,
		})
	}
	if len(d.Findings()) == 0 {
		t.Fatal("expected finding before TTL")
	}
	time.Sleep(100 * time.Millisecond)
	if got := len(d.Findings()); got != 0 {
		t.Fatalf("expected TTL expiry, got %d", got)
	}
}

func TestMaxWorkloadsEviction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxWorkloads = 2
	cfg.Window = time.Hour
	d := New(cfg)
	base := time.Now()
	for i := 0; i < 5; i++ {
		d.Observe(Event{
			Timestamp: base,
			Namespace: "ns", Pod: "pod-" + strconv.Itoa(i),
			DstIP: "10.0.0.1", DstPort: 80,
		})
	}
	d.mu.Lock()
	got := len(d.states)
	d.mu.Unlock()
	if got != 2 {
		t.Fatalf("tracked workloads = %d, want 2 (MaxWorkloads cap)", got)
	}
}

func TestFindingsAreDeepCopied(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinAttempts = 5
	cfg.MaxDestPorts = 3
	d := New(cfg)
	base := time.Now()
	for i := 0; i < 10; i++ {
		d.Observe(Event{
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Namespace: "ns", Pod: "p",
			DstIP: "10.0.0.5", DstPort: uint16(i + 1), SynOnly: true,
		})
	}
	findings := d.Findings()
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	findings[0].Signals[0] = "tampered"
	for _, f := range d.Findings() {
		for _, s := range f.Signals {
			if s == "tampered" {
				t.Fatal("mutating a returned Finding's slice leaked into internal state")
			}
		}
	}
}
