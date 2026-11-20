// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kerneldiag

import (
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildCorrelatesEvidenceAndSafeCommands(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:  "node-a",
		Stack: models.NodeStackStat{SoftnetDropped: 12},
		KernelNetwork: models.KernelNetworkSnapshot{
			Tunables: []models.KernelTunable{{Name: "net.core.netdev_max_backlog", Value: "1000"}, {Name: "net.core.rmem_max", Value: "212992"}},
			Counters: []models.KernelNetworkCounter{{Name: "Udp.RcvbufErrors", Value: 9}},
		},
	}}
	r := Build([]models.AgentStatus{a})
	if r.Summary.Nodes != 1 || r.Summary.Findings != 2 || r.Summary.Warnings != 2 {
		t.Fatalf("unexpected summary: %#v", r.Summary)
	}
	for _, f := range r.Nodes[0].Findings {
		if f.ApplyCommand == "" || f.RollbackCommand == "" {
			t.Fatalf("finding lacks reversible commands: %#v", f)
		}
		if strings.Contains(f.ApplyCommand, "212992") && !strings.Contains(f.RollbackCommand, "212992") {
			t.Fatalf("rollback must preserve observed value: %#v", f)
		}
	}
}

func TestBuildDoesNotRecommendFromTunablesAlone(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "quiet", KernelNetwork: models.KernelNetworkSnapshot{Tunables: []models.KernelTunable{{Name: "net.core.rmem_max", Value: "1024"}}}}}
	r := Build([]models.AgentStatus{a})
	if r.Summary.Findings != 0 {
		t.Fatalf("low value without drop evidence must not create a finding: %#v", r)
	}
}

func TestBuildFindsTCPConnectionQualityFromRetransmitsAndResets(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node: "node-a",
		KernelNetwork: models.KernelNetworkSnapshot{
			Counters: []models.KernelNetworkCounter{
				{Name: "Tcp.RetransSegs", Value: 200},
				{Name: "Tcp.OutRsts", Value: 300},
				{Name: "Tcp.EstabResets", Value: 100},
			},
		},
	}}
	r := Build([]models.AgentStatus{a})
	var found *models.KernelNetworkFinding
	for i := range r.Nodes[0].Findings {
		if r.Nodes[0].Findings[i].Layer == "tcp-connection-quality" {
			found = &r.Nodes[0].Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a tcp-connection-quality finding: %#v", r.Nodes[0].Findings)
	}
	if found.Tunable != "" || found.ApplyCommand != "" {
		t.Fatalf("tcp-connection-quality must never suggest a tunable — there is no safe buffer fix: %#v", found)
	}
	if !strings.Contains(strings.Join(found.Evidence, " "), "Tcp.RetransSegs=200") {
		t.Fatalf("evidence missing expected counter: %#v", found.Evidence)
	}
}

func TestBuildOmitsTCPConnectionQualityWhenCountersAreZero(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "quiet"}}
	r := Build([]models.AgentStatus{a})
	for _, f := range r.Nodes[0].Findings {
		if f.Layer == "tcp-connection-quality" {
			t.Fatalf("did not expect a finding with zero counters: %#v", f)
		}
	}
}

func TestBuildSkipsStaleAgent(t *testing.T) {
	r := Build([]models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "old", Stack: models.NodeStackStat{SoftnetDropped: 99}}}})
	if r.Summary.Nodes != 0 {
		t.Fatalf("stale node included: %#v", r)
	}
}

func TestBuildWindowUsesDeltasNotLifetimeCounters(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node: "node-a",
		KernelNetwork: models.KernelNetworkSnapshot{
			Tunables: []models.KernelTunable{{Name: "net.core.rmem_max", Value: "212992"}},
			Counters: []models.KernelNetworkCounter{{Name: "Udp.RcvbufErrors", Value: 900000}},
		},
	}}
	w := models.KernelNetworkWindow{Node: "node-a", Seconds: 300, Counters: []models.KernelNetworkCounterDelta{{Name: "Udp.RcvbufErrors", Delta: 0}}}
	r := BuildWindow([]models.AgentStatus{a}, []models.KernelNetworkWindow{w})
	if r.Summary.Findings != 0 {
		t.Fatalf("lifetime counter leaked into current-window findings: %#v", r)
	}
}

func TestBuildWindowLabelsDeltaEvidence(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node:          "node-a",
		KernelNetwork: models.KernelNetworkSnapshot{Tunables: []models.KernelTunable{{Name: "net.core.rmem_max", Value: "212992"}}},
	}}
	w := models.KernelNetworkWindow{Node: "node-a", Seconds: 60, Counters: []models.KernelNetworkCounterDelta{{Name: "Udp.RcvbufErrors", Delta: 9, PerSecond: 0.15}}}
	r := BuildWindow([]models.AgentStatus{a}, []models.KernelNetworkWindow{w})
	if r.Summary.Findings != 1 || r.Nodes[0].Findings[0].WindowSeconds != 60 {
		t.Fatalf("unexpected window finding: %#v", r)
	}
	if !strings.Contains(r.Nodes[0].Findings[0].Evidence[0], "_delta=") {
		t.Fatalf("evidence is not marked as delta: %#v", r.Nodes[0].Findings[0].Evidence)
	}
}

func TestBuildWindowWarmingSuppressesCumulativeFindings(t *testing.T) {
	a := models.AgentStatus{AgentReport: models.AgentReport{Node: "node-a", Stack: models.NodeStackStat{SoftnetDropped: 999}}}
	r := BuildWindow([]models.AgentStatus{a}, []models.KernelNetworkWindow{{Node: "node-a", Warming: true}})
	if r.Summary.Findings != 0 || r.Summary.Warming != 1 {
		t.Fatalf("warming window should suppress cumulative findings: %#v", r)
	}
}
