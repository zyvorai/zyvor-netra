// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestRunClassifiesAndSynthesizesHeuristic(t *testing.T) {
	snap := Snapshot{AgentsTotal: 2, HealthScore: 70, Blocked: 12}
	res := Run(context.Background(), snap, "why are packets being dropped?", nil, "")
	if res.Intent != IntentDrops {
		t.Fatalf("intent=%s", res.Intent)
	}
	if res.Engine != "heuristic" {
		t.Fatalf("engine=%s", res.Engine)
	}
	if res.Draft != nil {
		t.Fatalf("draft should be omitted for a diagnostic question: %+v", res.Draft)
	}
	if res.Brief.Question != "why are packets being dropped?" {
		t.Fatalf("question=%q", res.Brief.Question)
	}
	assertNode(t, res, "classify")
	assertNode(t, res, "gather")
	assertNode(t, res, "synthesize")
}

func TestRunInvestigateIntentSuggestsTimeline(t *testing.T) {
	snap := Snapshot{AgentsTotal: 1, HealthScore: 80, Blocked: 3}
	res := Run(context.Background(), snap, "why can't the pod reach the peer?", nil, "")
	if res.Intent != IntentInvestigate {
		t.Fatalf("intent=%s", res.Intent)
	}
	assertNode(t, res, "gather")
	found := false
	for _, s := range res.Brief.NextSteps {
		if strings.Contains(strings.ToLower(s), "investigate") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected investigate next step, got %#v", res.Brief.NextSteps)
	}
}

func TestRunDraftsWhenQuestionLooksLikeARule(t *testing.T) {
	snap := Snapshot{AgentsTotal: 1, HealthScore: 90}
	res := Run(context.Background(), snap, "deny dns malware.example", nil, "web:1")
	if res.Draft == nil || !res.Draft.Understood {
		t.Fatalf("expected understood draft, got %+v", res.Draft)
	}
	if res.ConversationID != "web:1" {
		t.Fatalf("conversationId=%q", res.ConversationID)
	}
	assertNode(t, res, "draft")
}

func TestRunEmptyQuestionStillBriefs(t *testing.T) {
	snap := Snapshot{AgentsTotal: 3, HealthScore: 96, Mode: "observe"}
	res := Run(context.Background(), snap, "   ", nil, "")
	if res.Intent != IntentBrief {
		t.Fatalf("intent=%s", res.Intent)
	}
	if strings.TrimSpace(res.Brief.Summary) == "" {
		t.Fatalf("expected a heuristic summary")
	}
}

func assertNode(t *testing.T, res AgentResult, name string) {
	t.Helper()
	for _, s := range res.Steps {
		if s.Node == name {
			return
		}
	}
	t.Fatalf("missing step %q in %+v", name, res.Steps)
}
