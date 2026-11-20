package leaseclock

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestActiveAndExpired(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	exp := now.Add(90 * time.Second)
	s := Build(models.EBPFFastPathConfig{Mode: "enforce", EnforceUntil: &exp}, now)
	if !s.Active || s.RemainingSec != 90 {
		t.Fatalf("%#v", s)
	}
	past := now.Add(-time.Second)
	s = Build(models.EBPFFastPathConfig{Mode: "observe", EnforceUntil: &past}, now)
	if !s.Expired || s.Active {
		t.Fatalf("%#v", s)
	}
}

func TestSubSecondLeaseStillActive(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	exp := now.Add(500 * time.Millisecond)
	s := Build(models.EBPFFastPathConfig{Mode: "enforce", EnforceUntil: &exp}, now)
	if !s.Active || s.Expired || s.RemainingSec != 1 {
		t.Fatalf("%#v", s)
	}
}
