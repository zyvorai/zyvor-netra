// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysctlaudit

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func agentWith(node string, entries ...models.SysctlAuditEntry) models.AgentStatus {
	return models.AgentStatus{
		AgentReport: models.AgentReport{Node: node, SysctlNetworkAudit: models.SysctlAuditSnapshot{Entries: entries}},
	}
}

func TestBuildCountsFindingsBySeverity(t *testing.T) {
	agents := []models.AgentStatus{
		agentWith("node-a",
			models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "0"}, // critical
			models.SysctlAuditEntry{Name: "net.ipv4.tcp_sack", Category: CategoryTCP, Value: "0"},                                    // warning
			models.SysctlAuditEntry{Name: "net.ipv4.ip_forward", Category: CategorySecurity, Value: "1"},                             // info
		),
	}
	got := Build(agents, 0)
	if got.Summary.Nodes != 1 {
		t.Fatalf("Summary.Nodes = %d, want 1", got.Summary.Nodes)
	}
	if got.Summary.Critical != 1 || got.Summary.Warnings != 1 || got.Summary.Informational != 1 {
		t.Fatalf("severity counts = %+v, want 1/1/1", got.Summary)
	}
}

func TestBuildSkipsStaleAgents(t *testing.T) {
	a := agentWith("node-a", models.SysctlAuditEntry{Name: "net.ipv4.tcp_syncookies", Category: CategorySecurity, Value: "0"})
	a.Stale = true
	got := Build([]models.AgentStatus{a}, 0)
	if got.Summary.Nodes != 0 || len(got.Nodes) != 0 {
		t.Fatalf("expected a stale agent to be skipped entirely, got %+v", got.Summary)
	}
}

func TestBuildCapsFindingsAtTopN(t *testing.T) {
	var entries []models.SysctlAuditEntry
	for range 10 {
		entries = append(entries, models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "0"})
	}
	got := Build([]models.AgentStatus{agentWith("node-a", entries...)}, 3)
	if len(got.Nodes[0].Findings) != 3 {
		t.Fatalf("len(Findings) = %d, want 3 (topN cap)", len(got.Nodes[0].Findings))
	}
	// Summary.Findings/Critical are true cluster-wide totals; only the
	// per-node display list is capped at topN.
	if got.Summary.Findings != 10 || got.Summary.Critical != 10 {
		t.Fatalf("Summary = %+v, want Findings=10 Critical=10 (uncapped totals)", got.Summary)
	}
}

func TestBuildOutliersFlagDisagreeingNodes(t *testing.T) {
	agents := []models.AgentStatus{
		agentWith("node-a", models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "1"}),
		agentWith("node-b", models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "1"}),
		agentWith("node-c", models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "0"}),
	}
	got := Build(agents, 0)
	if len(got.Outliers) != 1 {
		t.Fatalf("expected exactly one outlier group, got %d: %#v", len(got.Outliers), got.Outliers)
	}
	o := got.Outliers[0]
	if o.MajorityValue != "1" || len(o.OutlierNodes) != 1 || o.OutlierNodes[0] != "node-c" {
		t.Fatalf("unexpected outlier: %#v", o)
	}
}

func TestBuildOutliersIgnoreUnanimousValues(t *testing.T) {
	agents := []models.AgentStatus{
		agentWith("node-a", models.SysctlAuditEntry{Name: "net.ipv4.tcp_syncookies", Category: CategorySecurity, Value: "1"}),
		agentWith("node-b", models.SysctlAuditEntry{Name: "net.ipv4.tcp_syncookies", Category: CategorySecurity, Value: "1"}),
	}
	got := Build(agents, 0)
	if len(got.Outliers) != 0 {
		t.Fatalf("expected no outliers when every node agrees, got %#v", got.Outliers)
	}
}

func TestBuildOutliersToleratesDifferingInterfaceSets(t *testing.T) {
	// node-a only has eth0; node-b only has eth1 — these must not be
	// grouped together as if they were the same (name, interface) key.
	agents := []models.AgentStatus{
		agentWith("node-a", models.SysctlAuditEntry{Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0", Category: CategorySecurity, Value: "1"}),
		agentWith("node-b", models.SysctlAuditEntry{Name: "net.ipv4.conf.eth1.rp_filter", Interface: "eth1", Category: CategorySecurity, Value: "0"}),
	}
	got := Build(agents, 0)
	if len(got.Outliers) != 0 {
		t.Fatalf("different interfaces on different nodes should not be compared as outliers, got %#v", got.Outliers)
	}
}
