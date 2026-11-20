package observability

import (
	"github.com/zyvorai/netra/internal/models"
	"testing"
)

func TestTopologyAggregatesWorkloadEdges(t *testing.T) {
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Stats: []models.DestinationStat{
		{Namespace: "payments", Pod: "api-1", DestinationIP: "10.0.0.8", Port: 5432, Protocol: "TCP", Packets: 3, Bytes: 30},
		{Namespace: "payments", Pod: "api-1", DestinationIP: "10.0.0.8", Port: 5432, Protocol: "TCP", Packets: 2, Bytes: 20, Blocked: 1},
	}}}}
	got := Topology(agents, 10)
	if len(got) != 1 || got[0].Packets != 5 || got[0].Blocked != 1 || got[0].Destination != "10.0.0.8:5432" {
		t.Fatalf("got=%#v", got)
	}
}
