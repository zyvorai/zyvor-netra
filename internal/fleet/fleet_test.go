package fleet

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildSortsAndCounts(t *testing.T) {
	inv := Build([]models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "b", Workloads: []models.WorkloadIdentity{{Pod: "x"}}}, Stale: true},
		{AgentReport: models.AgentReport{Node: "a", Programs: []models.BPFProgramStat{{Name: "p", Attached: true}}}},
	}, time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC))
	if inv.AgentCount != 2 || inv.StaleAgents != 1 || inv.Workloads != 1 || inv.Nodes[0].Node != "a" {
		t.Fatalf("%#v", inv)
	}
}

func TestBuildPassesThroughNodeResources(t *testing.T) {
	inv := Build([]models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "a", NodeResources: models.NodeResourceSnapshot{
			Host: models.HostResourceSnapshot{CPUPercent: 55, MemoryUsedBytes: 100, MemoryTotalBytes: 200, LoadAvg1: 1.25},
		}}},
	}, time.Now())
	n := inv.Nodes[0]
	if n.CPUPercent != 55 || n.MemoryUsedBytes != 100 || n.MemoryTotalBytes != 200 || n.LoadAvg1 != 1.25 {
		t.Fatalf("resource fields did not pass through from AgentReport.NodeResources.Host: %#v", n)
	}
}
