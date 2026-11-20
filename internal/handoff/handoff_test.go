package handoff

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/auditstats"
	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/reasons"
	"github.com/zyvorai/netra/internal/report"
)

func TestMarkdownSafety(t *testing.T) {
	md := Markdown(Build(report.Snapshot{Headline: "quiet", Mode: "observe", HealthScore: 90, BaselineAt: time.Now(), RateBaselineAt: time.Now()}, coverage.Matrix{Quiet: true}, fleet.Inventory{AgentCount: 1}, auditstats.Summary{Total: 1}, reasons.Histogram{Total: 0}, time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)))
	if !strings.Contains(md, "observe-only") {
		t.Fatal(md)
	}
}
