// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package detective

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildPolicyDropFinding(t *testing.T) {
	r := Build([]models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node:             "n1",
			ConntrackEntries: 12,
			PolicyDrops: []models.PolicyDropStat{{
				Family: 4, Protocol: 6, Direction: 2, Reason: 3,
				SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 12345, DstPort: 80,
				Packets: 17, Bytes: 1000,
			}},
		},
	}}, models.EBPFFastPathConfig{BlockedPorts: []models.EBPFPortRule{{Protocol: "TCP", Port: 80}}}, 10)
	if r.Summary.ExactFindings != 1 {
		t.Fatalf("exact=%d summary=%+v", r.Summary.ExactFindings, r.Summary)
	}
	if r.Findings[0].Code != "port-deny" || r.Findings[0].Confidence != ConfidenceExact {
		t.Fatalf("finding=%+v", r.Findings[0])
	}
	if r.Summary.ConntrackEntries != 12 {
		t.Fatalf("ct=%d", r.Summary.ConntrackEntries)
	}
}

func TestBuildDistinguishesNetPolFromCIDRDeny(t *testing.T) {
	r := Build([]models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			PolicyDrops: []models.PolicyDropStat{
				{Family: 4, Protocol: 6, Direction: 2, Reason: 2, SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", Packets: 5},
				{Family: 4, Protocol: 6, Direction: 2, Reason: 9, SrcAddr: "10.0.0.3", DstAddr: "10.0.0.4", Packets: 9},
			},
		},
	}}, models.EBPFFastPathConfig{}, 10)
	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(r.Findings), r.Findings)
	}
	// Sorted by packets descending: netpol-deny (9) before cidr-deny (5).
	if r.Findings[0].Code != "netpol-deny" || r.Findings[0].Confidence != ConfidenceExact {
		t.Fatalf("expected netpol-deny first, got %+v", r.Findings[0])
	}
	if r.Findings[1].Code != "cidr-deny" {
		t.Fatalf("expected cidr-deny second, got %+v", r.Findings[1])
	}
	if r.Findings[0].Code == r.Findings[1].Code {
		t.Fatalf("netpol-deny and cidr-deny must remain distinguishable, both reported as %q", r.Findings[0].Code)
	}
}
