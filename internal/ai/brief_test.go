// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBuildBriefQuietCluster(t *testing.T) {
	b := BuildBrief(Snapshot{
		GeneratedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		AgentsTotal: 3,
		Workloads:   12,
		HealthScore: 96,
		Mode:        "observe",
	})
	if b.Engine != "heuristic" {
		t.Fatalf("engine=%s", b.Engine)
	}
	if b.Severity != "info" {
		t.Fatalf("severity=%s", b.Severity)
	}
	if !strings.Contains(strings.ToLower(b.Headline), "quiet") {
		t.Fatalf("headline=%q", b.Headline)
	}
}

func TestBuildBriefCriticalAnomaly(t *testing.T) {
	b := BuildBrief(Snapshot{
		AgentsTotal: 2,
		Anomalies: []Finding{{
			Severity: "critical",
			Kind:     "tcp-latency",
			Subject:  "default/api",
			Message:  "smoothed TCP RTT is above 750 ms",
		}},
	})
	if b.Severity != "critical" {
		t.Fatalf("severity=%s", b.Severity)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]Intent{
		"why are packets being dropped?": IntentDrops,
		"is there congestion on rcvbuf?": IntentCongestion,
		"listen queue backlog high?":     IntentCongestion,
		"why can't the pod reach the peer?": IntentInvestigate,
		"health score for dns":           IntentHealth,
		"draft a network policy":         IntentPolicy,
		"any new external exposure?":     IntentExposure,
		"are we in enforce mode?":        IntentMode,
		"any rare ja3 or ech blindness?": IntentTLS,
		"where is netlink route churn?":  IntentNetlink,
		"any shadow saas outside list?":  IntentExposure,
		"":                               IntentBrief,
	}
	for q, want := range cases {
		if got := Classify(q); got != want {
			t.Fatalf("Classify(%q)=%s want %s", q, got, want)
		}
	}
}

func TestAnswerFallsBackWithoutProvider(t *testing.T) {
	b := Answer(context.Background(), Snapshot{AgentsTotal: 1, HealthScore: 80}, "what is dropping?", nil, "")
	if b.Engine != "heuristic" {
		t.Fatalf("engine=%s", b.Engine)
	}
	if b.Question != "what is dropping?" {
		t.Fatalf("question=%q", b.Question)
	}
	if !strings.Contains(strings.ToLower(b.Headline), "drop") {
		t.Fatalf("expected drop specialization, headline=%q", b.Headline)
	}
}

func TestProviderFromEnvDisabledByDefault(t *testing.T) {
	t.Setenv("NETRA_AI_API_KEY", "")
	t.Setenv("NETRA_AI_BASE_URL", "")
	if ProviderFromEnv() != nil {
		t.Fatal("expected nil provider when no API key is set")
	}
	st := CurrentStatus()
	if st.Enabled || !st.HeuristicOnly {
		t.Fatalf("status=%+v", st)
	}
}
