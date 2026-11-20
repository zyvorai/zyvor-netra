package reasons

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildRanksBlocked(t *testing.T) {
	h := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Events: []models.FastPathEvent{
		{Action: "blocked", Reason: "deny-ip"},
		{Action: "blocked", Reason: "deny-ip"},
		{Action: "allow", Reason: ""},
	}}}}, time.Now().UTC())
	if h.Total != 3 || h.Blocked != 2 || h.Buckets[0].Reason != "deny-ip" {
		t.Fatalf("%#v", h)
	}
}
