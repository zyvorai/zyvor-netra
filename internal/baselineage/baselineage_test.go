package baselineage

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestMissingIsStale(t *testing.T) {
	s := Build(models.BehaviorBaseline{}, models.RateBaseline{}, time.Now(), time.Hour)
	if !s.Stale {
		t.Fatalf("%#v", s)
	}
}

func TestFresh(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	s := Build(models.BehaviorBaseline{CapturedAt: now.Add(-time.Minute), Entries: []models.BehaviorBaselineEntry{{}}}, models.RateBaseline{CapturedAt: now.Add(-time.Minute), Entries: []models.RateBaselineEntry{{}}}, now, time.Hour)
	if s.Stale || !s.BehaviorPresent {
		t.Fatalf("%#v", s)
	}
}
