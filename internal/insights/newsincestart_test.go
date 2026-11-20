// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func driftFixture() (models.BehaviorBaseline, []models.AgentStatus) {
	baseAgents := []models.AgentStatus{{AgentReport: models.AgentReport{TLSMetadata: []models.TLSMetadataStat{
		{Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "old.example.com", Handshakes: 5},
	}}}}
	b := CaptureBaseline(baseAgents, time.Unix(1000, 0))
	current := append([]models.AgentStatus(nil), baseAgents...)
	current[0].TLSMetadata = append(current[0].TLSMetadata, models.TLSMetadataStat{
		Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api", SNI: "new.example.com", Handshakes: 3,
	})
	return b, current
}

func timePtr(t time.Time) *time.Time { return &t }

func TestNewSinceStartKeepsFindingWhenPodStartedAfterBaseline(t *testing.T) {
	b, agents := driftFixture()
	pods := []models.PodInfo{{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: timePtr(b.CapturedAt.Add(time.Minute))}}
	out := NewSinceStart(b, agents, pods, 0)
	if len(out) != 1 {
		t.Fatalf("findings=%d, want 1", len(out))
	}
}

func TestNewSinceStartExcludesFindingWhenPodStartedBeforeBaseline(t *testing.T) {
	b, agents := driftFixture()
	pods := []models.PodInfo{{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: timePtr(b.CapturedAt.Add(-time.Hour))}}
	out := NewSinceStart(b, agents, pods, 0)
	if len(out) != 0 {
		t.Fatalf("findings=%d, want 0 (pod started before baseline)", len(out))
	}
}

func TestNewSinceStartExcludesUnknownPod(t *testing.T) {
	b, agents := driftFixture()
	out := NewSinceStart(b, agents, nil, 0)
	if len(out) != 0 {
		t.Fatalf("findings=%d, want 0 (no pod info at all)", len(out))
	}
}

func TestNewSinceStartExcludesPodWithNoRunningContainer(t *testing.T) {
	b, agents := driftFixture()
	pods := []models.PodInfo{{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: nil}}
	out := NewSinceStart(b, agents, pods, 0)
	if len(out) != 0 {
		t.Fatalf("findings=%d, want 0 (Started is nil)", len(out))
	}
}

func TestNewSinceStartExcludesHighRestartCount(t *testing.T) {
	b, agents := driftFixture()
	pods := []models.PodInfo{{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: timePtr(b.CapturedAt.Add(time.Minute)), RestartCount: 10}}
	out := NewSinceStart(b, agents, pods, 5)
	if len(out) != 0 {
		t.Fatalf("findings=%d, want 0 (restart count %d exceeds maxRestarts 5)", len(out), 10)
	}
}

func TestNewSinceStartZeroMaxRestartsDisablesFilter(t *testing.T) {
	b, agents := driftFixture()
	pods := []models.PodInfo{{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: timePtr(b.CapturedAt.Add(time.Minute)), RestartCount: 999}}
	out := NewSinceStart(b, agents, pods, 0)
	if len(out) != 1 {
		t.Fatalf("findings=%d, want 1 (maxRestarts<=0 disables the filter)", len(out))
	}
}

func TestNewSinceStartUsesMostRecentPodStartForSharedWorkload(t *testing.T) {
	b, agents := driftFixture()
	pods := []models.PodInfo{
		{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", Started: timePtr(b.CapturedAt.Add(-time.Hour))},
		{Namespace: "prod", Name: "api-2", OwnerKind: "Deployment", OwnerName: "api", Started: timePtr(b.CapturedAt.Add(time.Minute))},
	}
	out := NewSinceStart(b, agents, pods, 0)
	if len(out) != 1 {
		t.Fatalf("findings=%d, want 1 (workload source keyed by the most recent pod's start)", len(out))
	}
}

func TestNewSinceStartNoBaselineNoFindings(t *testing.T) {
	out := NewSinceStart(models.BehaviorBaseline{}, nil, nil, 0)
	if len(out) != 0 {
		t.Fatalf("findings=%d, want 0 (Drift itself does nothing without a captured baseline)", len(out))
	}
}
