// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysres

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildAggregatesFreshNodesOnly(t *testing.T) {
	now := time.Now()
	agents := []models.AgentStatus{
		{
			AgentReport: models.AgentReport{
				Node: "n1",
				NodeResources: models.NodeResourceSnapshot{
					Host: models.HostResourceSnapshot{CPUPercent: 40, CPUCores: 4, MemoryTotalBytes: 1000, MemoryUsedBytes: 400},
				},
			},
		},
		{
			Stale: true,
			AgentReport: models.AgentReport{
				Node: "n2",
				NodeResources: models.NodeResourceSnapshot{
					// A disconnected node's frozen last-known 99% CPU must
					// not pull the cluster average or "highest" toward it.
					Host: models.HostResourceSnapshot{CPUPercent: 99, CPUCores: 8, MemoryTotalBytes: 2000, MemoryUsedBytes: 1900},
				},
			},
		},
	}

	got := Build(agents, now, 20)

	if got.Summary.Nodes != 2 {
		t.Fatalf("Summary.Nodes = %d, want 2 (both nodes still listed)", got.Summary.Nodes)
	}
	if len(got.Nodes) != 2 {
		t.Fatalf("len(Nodes) = %d, want 2", len(got.Nodes))
	}
	if got.Summary.AvgCPUPercent != 40 {
		t.Fatalf("AvgCPUPercent = %v, want 40 (stale node excluded)", got.Summary.AvgCPUPercent)
	}
	if got.Summary.HighestCPUNode != "n1" {
		t.Fatalf("HighestCPUNode = %q, want n1 (stale node excluded)", got.Summary.HighestCPUNode)
	}
	if got.Summary.UsedMemoryBytes != 400 {
		t.Fatalf("UsedMemoryBytes = %d, want 400 (stale node's usage excluded)", got.Summary.UsedMemoryBytes)
	}
	// TotalCPUCores/TotalMemoryBytes are capacity, not usage — these
	// include stale nodes, since the hardware is still part of the fleet.
	if got.Summary.TotalCPUCores != 12 {
		t.Fatalf("TotalCPUCores = %d, want 12 (includes stale node's cores)", got.Summary.TotalCPUCores)
	}
}

func TestBuildStaleNodeStillListedButNotInTopWorkloads(t *testing.T) {
	now := time.Now()
	agents := []models.AgentStatus{
		{
			Stale: true,
			AgentReport: models.AgentReport{
				Node: "n1",
				NodeResources: models.NodeResourceSnapshot{
					Workloads: []models.WorkloadResourceStat{{Pod: "p1", CPUPercent: 90}},
				},
			},
		},
	}
	got := Build(agents, now, 20)
	if len(got.Nodes) != 1 {
		t.Fatalf("len(Nodes) = %d, want 1", len(got.Nodes))
	}
	if len(got.Nodes[0].Workloads) != 1 {
		t.Fatalf("expected the stale node's own Workloads to still be listed in its row")
	}
	if len(got.TopWorkloadsByCPU) != 0 {
		t.Fatalf("TopWorkloadsByCPU = %+v, want empty (stale node excluded from ranking)", got.TopWorkloadsByCPU)
	}
}

func TestBuildTopWorkloadsSortedAndCapped(t *testing.T) {
	now := time.Now()
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			NodeResources: models.NodeResourceSnapshot{
				Workloads: []models.WorkloadResourceStat{
					{Pod: "low", CPUPercent: 10},
					{Pod: "high", CPUPercent: 90},
					{Pod: "mid", CPUPercent: 50},
				},
			},
		},
	}}
	got := Build(agents, now, 2)
	if len(got.TopWorkloadsByCPU) != 2 {
		t.Fatalf("len(TopWorkloadsByCPU) = %d, want 2 (capped)", len(got.TopWorkloadsByCPU))
	}
	if got.TopWorkloadsByCPU[0].Pod != "high" || got.TopWorkloadsByCPU[1].Pod != "mid" {
		t.Fatalf("TopWorkloadsByCPU = %+v, want [high, mid] sorted descending", got.TopWorkloadsByCPU)
	}
}

func TestBuildDefaultsTopWorkloads(t *testing.T) {
	got := Build(nil, time.Now(), 0)
	if got.Summary.Nodes != 0 {
		t.Fatalf("expected empty response for no agents, got %+v", got.Summary)
	}
}

func TestBuildSetsGeneratedAt(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := Build(nil, now, 20)
	if !got.GeneratedAt.Equal(now) {
		t.Fatalf("GeneratedAt = %v, want %v", got.GeneratedAt, now)
	}
}

func TestBuildNodesSortedByName(t *testing.T) {
	agents := []models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "zeta"}},
		{AgentReport: models.AgentReport{Node: "alpha"}},
	}
	got := Build(agents, time.Now(), 20)
	if got.Nodes[0].Node != "alpha" || got.Nodes[1].Node != "zeta" {
		t.Fatalf("Nodes not sorted: %+v", got.Nodes)
	}
}
