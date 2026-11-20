// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCongestionBriefNoFindings(t *testing.T) {
	b := CongestionBrief(Snapshot{AgentsTotal: 1, HealthScore: 100})
	if b.Headline != "Kernel network stack pressure" {
		t.Fatalf("headline=%q", b.Headline)
	}
	if !strings.Contains(b.Summary, "No kernel-network congestion findings") {
		t.Fatalf("summary=%q, want the no-findings sentence", b.Summary)
	}
	if b.Severity != "info" {
		t.Fatalf("severity=%q, want info when no anomalies were added", b.Severity)
	}
}

func TestCongestionBriefWithFindingsReflectsCountsAndSeverity(t *testing.T) {
	snap := Snapshot{
		AgentsTotal:    1,
		KernelCritical: 1,
		KernelWarnings: 2,
		Anomalies: []Finding{
			{Severity: "critical", Kind: "kernel-network/qdisc", Subject: "n1", Message: "egress queue drops"},
			{Severity: "warning", Kind: "kernel-network/tcp-memory", Subject: "n1", Message: "TCP memory pressure"},
		},
	}
	b := CongestionBrief(snap)
	if !strings.Contains(b.Summary, "1 critical and 2 warning kernel-network finding(s)") {
		t.Fatalf("summary=%q", b.Summary)
	}
	// Severity rolls up through BuildBrief's own collectFindings/rollupSeverity
	// (brief.go) from snap.Anomalies — CongestionBrief must not compute its
	// own separate severity, or the two could disagree.
	if b.Severity != "critical" {
		t.Fatalf("severity=%q, want critical (rolled up from snap.Anomalies)", b.Severity)
	}
}

func TestAnswerEchoesConversationIDAndRecordsTurnsHeuristicOnly(t *testing.T) {
	resetConversations(t)
	snap := Snapshot{AgentsTotal: 1, HealthScore: 80}

	b1 := Answer(context.Background(), snap, "what is dropping?", nil, "conv1")
	if b1.ConversationID != "conv1" {
		t.Fatalf("ConversationID=%q, want conv1", b1.ConversationID)
	}
	b2 := Answer(context.Background(), snap, "what about health?", nil, "conv1")
	if b2.ConversationID != "conv1" {
		t.Fatalf("ConversationID=%q, want conv1", b2.ConversationID)
	}

	h := conversationHistory("conv1")
	if len(h) != 2 {
		t.Fatalf("history=%#v, want 2 recorded turns", h)
	}
	if h[0].Question != "what is dropping?" || h[1].Question != "what about health?" {
		t.Fatalf("history=%#v", h)
	}
}

func TestAnswerWithEmptyConversationIDRecordsNothing(t *testing.T) {
	resetConversations(t)
	snap := Snapshot{AgentsTotal: 1, HealthScore: 80}
	b := Answer(context.Background(), snap, "what is dropping?", nil, "")
	if b.ConversationID != "" {
		t.Fatalf("ConversationID=%q, want empty", b.ConversationID)
	}
	if len(convStore) != 0 {
		t.Fatalf("convStore=%#v, want empty — no id was supplied", convStore)
	}
}

func TestAnswerThreadsHistoryIntoProviderPrompt(t *testing.T) {
	resetConversations(t)
	var gotBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBodies = append(gotBodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "a rewritten answer"}}},
		})
	}))
	t.Cleanup(srv.Close)
	p := &Provider{BaseURL: srv.URL, APIKey: "test-key", Model: "test-model", HTTPClient: srv.Client()}
	snap := Snapshot{AgentsTotal: 1, HealthScore: 80}

	Answer(context.Background(), snap, "what is the top destination?", p, "conv1")
	if len(gotBodies) != 1 {
		t.Fatalf("got %d provider calls, want 1", len(gotBodies))
	}
	if strings.Contains(gotBodies[0], "Prior turns in this conversation") {
		t.Fatalf("first turn in a conversation must not include a history block: %s", gotBodies[0])
	}

	Answer(context.Background(), snap, "what about the second one?", p, "conv1")
	if len(gotBodies) != 2 {
		t.Fatalf("got %d provider calls, want 2", len(gotBodies))
	}
	second := gotBodies[1]
	if !strings.Contains(second, "Prior turns in this conversation") {
		t.Fatalf("second turn's prompt missing history block: %s", second)
	}
	if !strings.Contains(second, "what is the top destination?") {
		t.Fatalf("second turn's prompt missing the first question: %s", second)
	}
}
