package dnsboard

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestRanksFailures(t *testing.T) {
	b := Build([]models.AgentStatus{{AgentReport: models.AgentReport{DNSHealth: []models.DNSHealthStat{
		{Name: "a.example.", Queries: 10, Failures: 1},
		{Name: "b.example", Queries: 4, Failures: 4},
	}}}}, time.Now(), 10)
	if b.Failures != 5 || b.Rows[0].Name != "b.example" || b.Rows[0].FailRate != 1 {
		t.Fatalf("%#v", b)
	}
}
