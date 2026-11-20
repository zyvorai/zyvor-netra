// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package auditstats

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestSummarizeGroupsAndFilters(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 10, 15, 0, 0, time.UTC)
	events := []models.AuditEvent{
		{At: t0, Actor: "netractl", Action: "ebpf.mode"},
		{At: t0.Add(time.Hour), Actor: "netractl", Action: "ebpf.deny"},
		{At: t0.Add(2 * time.Hour), Actor: "mcp:hermes", Action: "ebpf.mode"},
		{At: t0.Add(3 * time.Hour), Actor: "api:10.0.0.1", Action: "insights.baseline"},
	}
	sum := Summarize(events, time.Time{}, time.Time{})
	if sum.Total != 4 {
		t.Fatalf("total=%d", sum.Total)
	}
	if len(sum.ByActor) != 3 || sum.ByActor[0].Key != "netractl" || sum.ByActor[0].Count != 2 {
		t.Fatalf("actors=%#v", sum.ByActor)
	}
	if len(sum.ByHour) != 4 {
		t.Fatalf("hours=%#v", sum.ByHour)
	}
	window := Summarize(events, t0.Add(30*time.Minute), t0.Add(2*time.Hour+time.Minute))
	if window.Total != 2 {
		t.Fatalf("window total=%d", window.Total)
	}
}
