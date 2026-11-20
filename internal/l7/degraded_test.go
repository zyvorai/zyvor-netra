// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestDegradedFalseWhenBothProgramsPresent(t *testing.T) {
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Programs: []models.BPFProgramStat{
		{Name: "netra_l7_cgroup_ingress", Attached: true},
		{Name: "netra_l7_cgroup_egress", Attached: true},
	}}}}
	degraded, nodes := Degraded(agents)
	if degraded || len(nodes) != 0 {
		t.Fatalf("degraded=%v nodes=%v, want false/empty", degraded, nodes)
	}
}

func TestDegradedTrueWhenProgramAbsentByName(t *testing.T) {
	// netra_l7_cgroup_egress is entirely missing — the real failure shape
	// (verifier-rejected programs are deleted from the collection, not
	// reported with Attached:false).
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Programs: []models.BPFProgramStat{
		{Name: "netra_l7_cgroup_ingress", Attached: true},
	}}}}
	degraded, nodes := Degraded(agents)
	if !degraded || len(nodes) != 1 || nodes[0] != "n1" {
		t.Fatalf("degraded=%v nodes=%v, want true/[n1]", degraded, nodes)
	}
}

func TestDegradedIgnoresAttachedFalseVsAbsence(t *testing.T) {
	// A program present but Attached:false is a different, already-visible
	// signal (BPF PROGRAM HEALTH on Health.tsx) — Degraded only cares about
	// name-absence, the verifier-rejection failure mode specifically.
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Programs: []models.BPFProgramStat{
		{Name: "netra_l7_cgroup_ingress", Attached: false},
		{Name: "netra_l7_cgroup_egress", Attached: false},
	}}}}
	degraded, _ := Degraded(agents)
	if degraded {
		t.Fatal("a present-but-detached program must not count as degraded by this check")
	}
}

func TestDegradedSkipsStaleAgents(t *testing.T) {
	agents := []models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1"}}}
	degraded, nodes := Degraded(agents)
	if degraded || len(nodes) != 0 {
		t.Fatalf("degraded=%v nodes=%v, want false/empty for a stale agent", degraded, nodes)
	}
}

func TestDegradedMultipleNodesSorted(t *testing.T) {
	agents := []models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "n2", Programs: nil}},
		{AgentReport: models.AgentReport{Node: "n1", Programs: nil}},
	}
	degraded, nodes := Degraded(agents)
	if !degraded || len(nodes) != 2 || nodes[0] != "n1" || nodes[1] != "n2" {
		t.Fatalf("degraded=%v nodes=%v", degraded, nodes)
	}
}
