// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/notify"
)

func TestShouldTrigger(t *testing.T) {
	cases := []struct {
		ev   notify.Event
		want bool
	}{
		{notify.Event{Source: "kerneldiag", Severity: "critical"}, true},
		{notify.Event{Source: "kerneldiag", Severity: "warning"}, false},
		{notify.Event{Source: "dropdiag-baseline", Kind: "kernel-drop-spike", Severity: "critical"}, true},
		{notify.Event{Source: "dropdiag-baseline", Kind: "policy-drop-spike", Severity: "critical"}, true},
		{notify.Event{Source: "dropdiag-baseline", Kind: "kernel-drop-spike", Severity: "warning"}, false},
		{notify.Event{Source: "dropdiag", Kind: "softnet-drop", Severity: "critical"}, true},
		{notify.Event{Source: "dropdiag", Kind: "interface-drop", Severity: "critical"}, false},
		{notify.Event{Source: "health", Kind: "tcp-rto", Severity: "critical"}, false},
	}
	for _, tc := range cases {
		if got := ShouldTrigger(tc.ev); got != tc.want {
			t.Fatalf("%+v: got %v want %v", tc.ev, got, tc.want)
		}
	}
}

func TestAutoCaptureCooldownAndEnrichment(t *testing.T) {
	var started []models.CaptureSpec
	var mu sync.Mutex
	active := map[string]models.CaptureSpec{}
	auto := NewAutoCapture(discardLogger(), AutoConfig{
		Enabled: true, Duration: time.Minute, Cooldown: time.Hour, Protocol: "tcp", MaxPPS: 500, MaxConcurrent: 5,
	}, func(spec models.CaptureSpec) models.CaptureSpec {
		mu.Lock()
		defer mu.Unlock()
		started = append(started, spec)
		active[spec.Node] = spec
		return spec
	}, func(node string) *models.CaptureSpec {
		mu.Lock()
		defer mu.Unlock()
		if s, ok := active[node]; ok {
			out := s
			return &out
		}
		return nil
	}, func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(active)
	}, func(notify.Event) bool { return true })

	now := time.Now()
	agents := []models.AgentStatus{{
		Node: "n1",
		PolicyDrops: []models.PolicyDropStat{{
			Protocol: 6, DstAddr: "10.0.0.5", DstPort: 443, Packets: 100,
		}},
	}}
	ev := notify.Event{
		Source: "dropdiag-baseline", Kind: "policy-drop-spike", Severity: "critical",
		Subject: "n1/denied", Node: "n1",
	}
	auto.MaybeStart(now, ev, agents)
	mu.Lock()
	if len(started) != 1 {
		t.Fatalf("started=%d", len(started))
	}
	if started[0].Host != "10.0.0.5" || started[0].Port != 443 || started[0].Protocol != "tcp" {
		t.Fatalf("enrichment: %+v", started[0])
	}
	if !IsAutoCaptureRequestor(started[0].Requestor) {
		t.Fatalf("requestor=%q", started[0].Requestor)
	}
	mu.Unlock()

	var stagedNode string
	auto.WithStage(func(node string, ctx models.DropIncidentContext) {
		stagedNode = node
		if ctx.Node.Name != "n1" {
			t.Errorf("staged node name %q", ctx.Node.Name)
		}
	})
	// Cooldown is still armed from the start above; reset it so the stage
	// path runs, and clear the active session the same way the rest of
	// this test does.
	auto.mu.Lock()
	delete(auto.lastByNode, "n1")
	auto.mu.Unlock()
	mu.Lock()
	delete(active, "n1")
	mu.Unlock()
	auto.MaybeStart(now.Add(time.Minute), ev, agents)
	if stagedNode != "n1" {
		t.Fatalf("StageContext node=%q", stagedNode)
	}
	mu.Lock()
	if len(started) != 2 {
		t.Fatalf("stage start count=%d", len(started))
	}
	mu.Unlock()

	// Cooldown should suppress a third start.
	mu.Lock()
	delete(active, "n1")
	mu.Unlock()
	auto.MaybeStart(now.Add(time.Minute), ev, agents)
	mu.Lock()
	if len(started) != 2 {
		t.Fatalf("cooldown failed, started=%d", len(started))
	}
	mu.Unlock()
}

func TestResolveNode(t *testing.T) {
	if got := resolveNode(notify.Event{Node: "a"}, nil); got != "a" {
		t.Fatal(got)
	}
	if got := resolveNode(notify.Event{Subject: "node1/softnet-backlog"}, nil); got != "node1" {
		t.Fatal(got)
	}
}
