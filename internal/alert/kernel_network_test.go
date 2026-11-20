// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func kernelWindowFixture(node string, retransSegs uint64) []models.KernelNetworkWindow {
	return []models.KernelNetworkWindow{{
		Node: node, Seconds: 300, Warming: false,
		Counters: []models.KernelNetworkCounterDelta{
			{Name: "Tcp.RetransSegs", Delta: retransSegs, PerSecond: float64(retransSegs) / 300},
		},
	}}
}

func kernelAgentFixture(node string) []models.AgentStatus {
	return []models.AgentStatus{{AgentReport: models.AgentReport{Node: node}}}
}

func TestKernelNetworkEventsFiresOnNewFinding(t *testing.T) {
	p := &Poller{
		cfg:                Config{Cooldown: time.Minute, KernelWindow: 5 * time.Minute},
		dedup:              newDedupState(),
		fetchKernelWindows: func(time.Duration) []models.KernelNetworkWindow { return kernelWindowFixture("n1", 6000) },
	}
	base := time.Unix(1000, 0)
	events := p.kernelNetworkEvents(base, kernelAgentFixture("n1"))
	if len(events) != 1 {
		t.Fatalf("events=%#v, want exactly 1 from the tcp-connection-quality finding", events)
	}
	if events[0].Source != "kerneldiag" || events[0].Kind != "tcp-connection-quality" {
		t.Fatalf("unexpected event: %#v", events[0])
	}
}

func TestKernelNetworkEventsSuppressesRepeatWithinCooldown(t *testing.T) {
	p := &Poller{
		cfg:                Config{Cooldown: time.Hour, KernelWindow: 5 * time.Minute},
		dedup:              newDedupState(),
		fetchKernelWindows: func(time.Duration) []models.KernelNetworkWindow { return kernelWindowFixture("n1", 6000) },
	}
	base := time.Unix(1000, 0)
	if got := p.kernelNetworkEvents(base, kernelAgentFixture("n1")); len(got) != 1 {
		t.Fatalf("first tick should fire: %#v", got)
	}
	if got := p.kernelNetworkEvents(base.Add(time.Second), kernelAgentFixture("n1")); len(got) != 0 {
		t.Fatalf("repeat within cooldown should be suppressed: %#v", got)
	}
}

func TestKernelNetworkEventsReturnsNilWithoutFetchFunc(t *testing.T) {
	p := &Poller{cfg: Config{Cooldown: time.Minute, KernelWindow: 5 * time.Minute}, dedup: newDedupState()}
	if got := p.kernelNetworkEvents(time.Unix(1000, 0), kernelAgentFixture("n1")); got != nil {
		t.Fatalf("events=%#v, want nil when fetchKernelWindows is unset (tests that construct a Poller directly, not via New)", got)
	}
}

func TestKernelNetworkEventsNoFindingsWhenClean(t *testing.T) {
	p := &Poller{
		cfg:                Config{Cooldown: time.Minute, KernelWindow: 5 * time.Minute},
		dedup:              newDedupState(),
		fetchKernelWindows: func(time.Duration) []models.KernelNetworkWindow { return kernelWindowFixture("n1", 0) },
	}
	if got := p.kernelNetworkEvents(time.Unix(1000, 0), kernelAgentFixture("n1")); len(got) != 0 {
		t.Fatalf("events=%#v, want none when the counter delta is zero", got)
	}
}
