package nsheat

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestRanksNamespaces(t *testing.T) {
	b := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Stats: []models.DestinationStat{
		{Namespace: "prod", DestinationIP: "1.1.1.1", Packets: 5},
		{Namespace: "prod", DestinationIP: "8.8.8.8", Packets: 2},
		{Namespace: "dev", DestinationIP: "1.1.1.1", Packets: 1},
	}}}}, time.Now(), 10)
	if b.Count != 2 || b.Rows[0].Namespace != "prod" || b.Rows[0].Dests != 2 {
		t.Fatalf("%#v", b)
	}
}
