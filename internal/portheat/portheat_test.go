package portheat

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestRanksPorts(t *testing.T) {
	b := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Stats: []models.DestinationStat{
		{Port: 443, Protocol: "tcp", Packets: 9},
		{Port: 443, Protocol: "TCP", Packets: 1},
		{Port: 53, Protocol: "udp", Packets: 3},
	}}}}, time.Now(), 10)
	if b.Count != 2 || b.Rows[0].Key != "TCP/443" || b.Rows[0].Flows != 2 {
		t.Fatalf("%#v", b)
	}
}
