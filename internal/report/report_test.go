// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package report

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildObserveQuiet(t *testing.T) {
	at := time.Date(2026, 9, 14, 15, 0, 0, 0, time.UTC)
	s := Build(Input{
		GeneratedAt:   at,
		Version:       "0.27.71",
		Mode:          "observe",
		ScopeMode:     "all",
		Agents:        3,
		HealthScore:   92,
		Packets:       1000,
		BaselineAt:    at.Add(-time.Hour),
		Anomalies:     nil,
		DriftFindings: 0,
	})
	if !strings.Contains(s.Headline, "Observe-mode") {
		t.Fatalf("headline: %s", s.Headline)
	}
	md := Markdown(s)
	if !strings.Contains(md, "# Netra operator report") {
		t.Fatal(md)
	}
	if !strings.Contains(md, "observe-only") {
		t.Fatal("safety note missing")
	}
	if strings.Contains(md, "stale threshold") {
		t.Fatalf("quiet cluster should not flag stale: %s", md)
	}
}

func TestBuildEnforceAndStale(t *testing.T) {
	until := time.Date(2026, 9, 14, 16, 0, 0, 0, time.UTC)
	s := Build(Input{
		GeneratedAt:    until.Add(-time.Minute),
		Mode:           "enforce",
		LeaseExpiresAt: until,
		Agents:         2,
		StaleAgents:    1,
		HealthScore:    40,
		Anomalies: []models.NetworkHealthAnomaly{{
			Severity: "critical",
			Kind:     "high_rtt",
			Message:  "srtt elevated",
		}},
		DriftFindings: 2,
		Incidents:     1,
		IncidentSamples: []models.IncidentCluster{{
			SourceKey: "workload:default:deploy:api",
			Severity:  "high",
			Findings:  []models.IncidentFinding{{Kind: "health"}, {Kind: "drift"}},
		}},
		Audit: []models.AuditEvent{{
			At:     until.Add(-2 * time.Minute),
			Actor:  "netractl",
			Action: "ebpf.mode",
			Target: "enforce",
		}},
	})
	if !strings.Contains(s.Headline, "Degraded") {
		t.Fatalf("headline: %s", s.Headline)
	}
	joined := strings.Join(s.Attention, "\n")
	for _, needle := range []string{"stale", "enforce until", "health score", "behavior-drift", "srtt elevated", "incident"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("attention missing %q:\n%s", needle, joined)
		}
	}
	if len(s.RecentAudit) != 1 {
		t.Fatalf("audit: %#v", s.RecentAudit)
	}
}

func TestBuildFlagsMissingBaseline(t *testing.T) {
	s := Build(Input{Mode: "observe", Agents: 1, HealthScore: 80})
	found := false
	for _, a := range s.Attention {
		if strings.Contains(a, "no behavior baseline") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected baseline hint, got %#v", s.Attention)
	}
}
