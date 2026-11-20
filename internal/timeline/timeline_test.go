// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package timeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestExplainAuditEventUsesSpecificTemplate(t *testing.T) {
	ev := models.AuditEvent{Actor: "alice", Action: "ebpf.mode", Target: "enforce"}
	got := ExplainAuditEvent(ev)
	if !strings.Contains(got, "alice") || !strings.Contains(got, "enforce") {
		t.Fatalf("got %q", got)
	}
}

func TestExplainAuditEventGenericFallback(t *testing.T) {
	ev := models.AuditEvent{Actor: "bob", Action: "ebpf.allow-cidr.add", Target: "10.0.0.0/8"}
	got := ExplainAuditEvent(ev)
	if !strings.Contains(got, "bob") || !strings.Contains(got, "added") || !strings.Contains(got, "CIDR allow rule") || !strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("got %q", got)
	}
}

func TestExplainAuditEventDenyNotConfusedWithDenyCapability(t *testing.T) {
	got := ExplainAuditEvent(models.AuditEvent{Actor: "a", Action: "ebpf.deny-capability.add", Target: "cap-1"})
	if !strings.Contains(got, "capability-gated deny rule") {
		t.Fatalf("deny-capability matched wrong noun: %q", got)
	}
	got2 := ExplainAuditEvent(models.AuditEvent{Actor: "a", Action: "ebpf.deny.add", Target: "1.2.3.4"})
	if strings.Contains(got2, "capability") {
		t.Fatalf("plain ebpf.deny.add matched the deny-capability template: %q", got2)
	}
}

func TestExplainAuditEventUnknownActionNeverEmpty(t *testing.T) {
	got := ExplainAuditEvent(models.AuditEvent{Actor: "x", Action: "some.brand.new.action", Target: "t"})
	if got == "" || !strings.Contains(got, "some.brand.new.action") {
		t.Fatalf("expected a non-empty last-resort sentence naming the action, got %q", got)
	}
}

func TestExplainAuditEventNeverEmptyForMissingActorOrTarget(t *testing.T) {
	got := ExplainAuditEvent(models.AuditEvent{Action: "ebpf.allow.add"})
	if got == "" {
		t.Fatal("expected a non-empty sentence even with no actor/target")
	}
}

func TestDigestTransitionsSkipsUnfingerprintedSamples(t *testing.T) {
	t0 := time.Now()
	samples := []models.ClusterHealthSample{
		{At: t0, Fingerprint: "fp1", Severity: "info", HealthScore: 100},
		{At: t0.Add(time.Minute), Fingerprint: "", Severity: "critical", HealthScore: 10}, // ebpfHealth sample, no fingerprint
		{At: t0.Add(2 * time.Minute), Fingerprint: "fp1", Severity: "info", HealthScore: 95},
		{At: t0.Add(3 * time.Minute), Fingerprint: "fp2", Severity: "warning", HealthScore: 80},
	}
	out := digestTransitions(samples)
	if len(out) != 1 {
		t.Fatalf("transitions=%d, want 1 (fp1->fp1 across the unfingerprinted sample must not count, only fp1->fp2)", len(out))
	}
	if out[0].Severity != "warning" {
		t.Fatalf("transition severity=%q, want warning", out[0].Severity)
	}
}

func TestBuildMergesAndSortsByTime(t *testing.T) {
	t0 := time.Now()
	audit := []models.AuditEvent{{At: t0.Add(2 * time.Minute), Actor: "a", Action: "ebpf.mode", Target: "enforce"}}
	samples := []models.ClusterHealthSample{
		{At: t0, Fingerprint: "fp1", Severity: "info", HealthScore: 100},
		{At: t0.Add(time.Minute), Fingerprint: "fp2", Severity: "critical", HealthScore: 10},
	}
	tl := Build(audit, samples, time.Time{})
	if len(tl.Entries) != 2 {
		t.Fatalf("entries=%d, want 2", len(tl.Entries))
	}
	if tl.Entries[0].Kind != "digest-transition" || tl.Entries[1].Kind != "audit" {
		t.Fatalf("entries not sorted by time: %#v", tl.Entries)
	}
	if tl.Engine != "heuristic" {
		t.Fatalf("engine=%q, want heuristic (no LLM rewrite attempted by Build)", tl.Engine)
	}
}

func TestBuildFiltersBySince(t *testing.T) {
	t0 := time.Now()
	audit := []models.AuditEvent{
		{At: t0, Actor: "a", Action: "ebpf.mode", Target: "observe"},
		{At: t0.Add(time.Hour), Actor: "a", Action: "ebpf.mode", Target: "enforce"},
	}
	tl := Build(audit, nil, t0.Add(30*time.Minute))
	if len(tl.Entries) != 1 {
		t.Fatalf("entries=%d, want 1 (only the event after since)", len(tl.Entries))
	}
	if tl.Since == nil {
		t.Fatal("expected Since to be set")
	}
}

func TestNarrateNoProviderReturnsUnchanged(t *testing.T) {
	tl := models.Timeline{Entries: []models.TimelineEntry{{Text: "x"}}, Engine: "heuristic"}
	out := Narrate(context.Background(), tl, nil)
	if out.Engine != "heuristic" || out.Prose != "" {
		t.Fatalf("expected unchanged timeline with nil provider, got %#v", out)
	}
}
