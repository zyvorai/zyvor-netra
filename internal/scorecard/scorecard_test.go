package scorecard

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/reasons"
	"github.com/zyvorai/netra/internal/report"
)

func TestBandDropsOnStale(t *testing.T) {
	c := Build(report.Snapshot{HealthScore: 90, Headline: "ok"}, coverage.Matrix{}, fleet.Inventory{StaleAgents: 2}, reasons.Histogram{}, time.Now())
	if c.Score >= 90 || c.Band == "green" {
		t.Fatalf("%#v", c)
	}
}
