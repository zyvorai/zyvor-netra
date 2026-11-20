// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package alert

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestRestartTrackerFirstSightingIsNeverJustRestarted(t *testing.T) {
	rt := newRestartTracker()
	if rt.justRestarted("workload:a", 3) {
		t.Fatal("first sighting of a source must never report justRestarted")
	}
}

func TestRestartTrackerDetectsIncrease(t *testing.T) {
	rt := newRestartTracker()
	rt.justRestarted("workload:a", 3)
	if !rt.justRestarted("workload:a", 4) {
		t.Fatal("expected justRestarted=true when restart count increased")
	}
}

func TestRestartTrackerSameOrLowerCountIsNotARestart(t *testing.T) {
	rt := newRestartTracker()
	rt.justRestarted("workload:a", 3)
	if rt.justRestarted("workload:a", 3) {
		t.Fatal("unchanged restart count must not report justRestarted")
	}
}

func TestRestartCountsBySourceUsesMaxAcrossSharedWorkload(t *testing.T) {
	pods := []models.PodInfo{
		{Namespace: "prod", Name: "api-1", OwnerKind: "Deployment", OwnerName: "api", RestartCount: 2},
		{Namespace: "prod", Name: "api-2", OwnerKind: "Deployment", OwnerName: "api", RestartCount: 7},
	}
	counts := restartCountsBySource(pods)
	if counts["workload:prod:deployment:api"] != 7 {
		t.Fatalf("workload restart count=%d, want 7", counts["workload:prod:deployment:api"])
	}
	if counts["pod:prod:api-1"] != 2 || counts["pod:prod:api-2"] != 7 {
		t.Fatalf("per-pod counts=%#v", counts)
	}
}
