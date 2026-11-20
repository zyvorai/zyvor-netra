// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ebpfmaps

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildAndFormat(t *testing.T) {
	cfg := models.EBPFFastPathConfig{
		Mode:         "observe",
		Revision:     7,
		BlockedIPv4:  []string{"203.0.113.9", "198.51.100.1"},
		BlockedDNS:   []string{"evil.example"},
		AllowedCIDRs: []models.EBPFCIDRRule{{CIDR: "10.0.0.0/8", Direction: "egress"}},
		RateLimits:   []models.EBPFRateLimit{{Destination: "203.0.113.50", PPS: 100, BPS: 1000}},
		ScopeMode:    "all",
	}
	rep := Build(cfg, time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC))
	if rep.FilledMaps < 3 {
		t.Fatalf("filled=%d", rep.FilledMaps)
	}
	if rep.TotalEntries < 5 {
		t.Fatalf("entries=%d", rep.TotalEntries)
	}
	var blocked *MapView
	for i := range rep.Maps {
		if rep.Maps[i].ID == "blocked_v4" {
			blocked = &rep.Maps[i]
			break
		}
	}
	if blocked == nil || blocked.Count != 2 || len(blocked.Entries) != 2 {
		t.Fatalf("%#v", blocked)
	}

	var b strings.Builder
	Format(&b, rep)
	out := b.String()
	for _, want := range []string{"DENY", "203.0.113.9", "evil.example", "ALLOW", "10.0.0.0/8", "RATE LIMITS", "pps=100", "Empty maps"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
