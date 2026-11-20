// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package coverage

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildQuietAndGaps(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)
	m := Build([]models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "b", Mode: "observe", Hooks: []string{"cgroup_skb"}, Programs: []models.BPFProgramStat{{Name: "netra_egress", Attached: true}}}, Stale: false},
		{AgentReport: models.AgentReport{Node: "a", Mode: "observe", MissingMaps: []string{"blocked_v4"}, Programs: []models.BPFProgramStat{{Name: "netra_ingress", Attached: false, Type: "sched_cls"}}}, Stale: true},
	}, now)
	if m.AgentCount != 2 || m.StaleAgents != 1 || m.DetachedPrograms != 1 || m.MissingMapEntries != 1 || m.Quiet {
		t.Fatalf("%#v", m)
	}
	if m.Nodes[0].Node != "a" || len(m.Nodes[0].Detached) != 1 {
		t.Fatalf("sort/detach: %#v", m.Nodes)
	}
	quiet := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n", Programs: []models.BPFProgramStat{{Name: "x", Attached: true}}}}}, now)
	if !quiet.Quiet {
		t.Fatalf("expected quiet: %#v", quiet)
	}
}
