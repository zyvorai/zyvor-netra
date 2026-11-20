package talkers

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestRanksByPackets(t *testing.T) {
	b := Build([]models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "a", Stats: []models.DestinationStat{{DestinationIP: "203.0.113.1", Packets: 3}}}},
		{AgentReport: models.AgentReport{Node: "b", Stats: []models.DestinationStat{{DestinationIP: "203.0.113.1", Packets: 2}, {DestinationIP: "198.51.100.2", Packets: 9}}}},
	}, time.Now(), 10)
	if b.Count != 2 || b.Rows[0].Destination != "198.51.100.2" || b.Rows[1].Packets != 5 || b.Rows[1].Nodes != 2 {
		t.Fatalf("%#v", b)
	}
}
