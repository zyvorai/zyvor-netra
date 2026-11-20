// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestExplainFindingRanksRelatedAndPageNextSteps(t *testing.T) {
	snap := Snapshot{
		AgentsTotal: 1,
		HealthScore: 70,
		Anomalies: []Finding{
			{Kind: "drop", Subject: "egress", Message: "policy drop egress", Severity: "warning"},
			{Kind: "rtt", Subject: "n1", Message: "high rtt", Severity: "info"},
		},
	}
	b := ExplainFinding(context.Background(), snap, ExplainRequest{
		Kind:     "drop",
		Subject:  "egress",
		Message:  "skb dropped by NetPol",
		Page:     "drops",
		Severity: "warning",
	}, nil)
	if !strings.Contains(b.Summary, "skb dropped by NetPol") {
		t.Fatalf("summary missing finding message: %q", b.Summary)
	}
	if !strings.Contains(strings.ToLower(b.Headline), "drop") {
		t.Fatalf("headline=%q", b.Headline)
	}
	foundRelated := false
	for _, f := range b.Findings {
		if strings.Contains(f.Message, "policy drop") {
			foundRelated = true
		}
	}
	if !foundRelated {
		t.Fatalf("expected related anomaly in findings: %#v", b.Findings)
	}
	foundStep := false
	for _, s := range b.NextSteps {
		if strings.Contains(strings.ToLower(s), "diagnose") || strings.Contains(strings.ToLower(s), "drops") {
			foundStep = true
		}
	}
	if !foundStep {
		t.Fatalf("expected drops next step: %#v", b.NextSteps)
	}
}

func TestExplainQuestionPrefersExplicitQuestion(t *testing.T) {
	q := ExplainQuestion(ExplainRequest{Question: " why this? ", Kind: "drop"})
	if q != "why this?" {
		t.Fatalf("q=%q", q)
	}
}
