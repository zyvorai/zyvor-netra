// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package playbook

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/report"
)

func TestBuildQuietCluster(t *testing.T) {
	b := Build(report.Snapshot{
		Headline:       "quiet",
		Mode:           "observe",
		Agents:         2,
		HealthScore:    90,
		BaselineAt:     time.Now(),
		RateBaselineAt: time.Now(),
	})
	if b.Count != 1 || b.Steps[0].ID != "quiet" {
		t.Fatalf("want quiet-only book, got %#v", b)
	}
	if b.Steps[0].AutoApply {
		t.Fatal("AutoApply must stay false")
	}
	if !strings.Contains(Markdown(b), "review-only") {
		t.Fatal("markdown missing safety line")
	}
}

func TestBuildStacksAttentionSteps(t *testing.T) {
	b := Build(report.Snapshot{
		Mode:          "enforce",
		StaleAgents:   1,
		HealthScore:   40,
		DriftFindings: 2,
		RateDrift:     1,
		HighExposure:  1,
		Incidents:     2,
		DNSFailures:   4,
		Blocked:       9,
	})
	seen := map[string]bool{}
	for _, s := range b.Steps {
		seen[s.ID] = true
		if s.AutoApply || !s.ReviewOnly {
			t.Fatalf("step %s must be review-only", s.ID)
		}
	}
	for _, id := range []string{"stale-agents", "capture-baseline", "enforce-lease", "health-floor", "review-drift", "review-exposure", "review-incidents"} {
		if !seen[id] {
			t.Fatalf("missing step %s in %#v", id, seen)
		}
	}
	if seen["quiet"] {
		t.Fatal("quiet step should not mix with attention steps")
	}
}
