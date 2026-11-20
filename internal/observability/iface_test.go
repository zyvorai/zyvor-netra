// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package observability

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestInterfaceSummaryAggregatesPerInterface(t *testing.T) {
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", InterfaceFlows: []models.InterfaceFlowStat{
		{IfIndex: 2, Interface: "eth0", DestinationIP: "1.1.1.1", DestinationPort: 443, Packets: 10, Bytes: 1000, Blocked: 1},
		{IfIndex: 2, Interface: "eth0", DestinationIP: "2.2.2.2", DestinationPort: 80, Packets: 5, Bytes: 500},
		{IfIndex: 3, Interface: "eth1", DestinationIP: "3.3.3.3", DestinationPort: 53, Packets: 20, Bytes: 200},
	}}}}
	r := InterfaceSummary(agents, 10)
	if len(r.Nodes) != 1 || r.Nodes[0].Node != "n1" {
		t.Fatalf("unexpected nodes: %+v", r.Nodes)
	}
	ifaces := r.Nodes[0].Interfaces
	if len(ifaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d: %+v", len(ifaces), ifaces)
	}
	var eth0 *models.InterfaceSummary
	for i := range ifaces {
		if ifaces[i].Interface == "eth0" {
			eth0 = &ifaces[i]
		}
	}
	if eth0 == nil {
		t.Fatalf("expected eth0 in %+v", ifaces)
	}
	if eth0.Packets != 15 || eth0.Bytes != 1500 || eth0.Blocked != 1 {
		t.Fatalf("unexpected eth0 rollup: %+v", eth0)
	}
	if len(eth0.TopDests) != 2 {
		t.Fatalf("expected 2 top destinations for eth0, got %+v", eth0.TopDests)
	}
}

func TestInterfaceSummarySkipsStaleAndEmptyAgents(t *testing.T) {
	agents := []models.AgentStatus{
		{Stale: true, AgentReport: models.AgentReport{Node: "stale", InterfaceFlows: []models.InterfaceFlowStat{{IfIndex: 1, Packets: 999}}}},
		{AgentReport: models.AgentReport{Node: "empty"}},
	}
	r := InterfaceSummary(agents, 10)
	if len(r.Nodes) != 0 {
		t.Fatalf("expected no nodes, got %+v", r.Nodes)
	}
}

func TestInterfaceSummaryFallsBackToIfIndexWhenNameMissing(t *testing.T) {
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", InterfaceFlows: []models.InterfaceFlowStat{
		{IfIndex: 7, DestinationIP: "1.1.1.1", Packets: 1},
	}}}}
	r := InterfaceSummary(agents, 10)
	if len(r.Nodes[0].Interfaces) != 1 || r.Nodes[0].Interfaces[0].Interface != "7" {
		t.Fatalf("expected fallback to ifindex string, got %+v", r.Nodes[0].Interfaces)
	}
}
