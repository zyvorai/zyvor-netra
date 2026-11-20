package protomix

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestMix(t *testing.T) {
	m := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Stats: []models.DestinationStat{
		{Protocol: "tcp", Packets: 9}, {Protocol: "UDP", Packets: 2}, {Protocol: "tcp", Packets: 1},
	}}}}, time.Now())
	if len(m.Rows) != 2 || m.Rows[0].Protocol != "TCP" || m.Rows[0].Flows != 2 {
		t.Fatalf("%#v", m)
	}
}
