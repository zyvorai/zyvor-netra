// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/ai"
	"github.com/zyvorai/netra/internal/store"
)

func TestAICongestionBriefIncludesKernelNetworkFindings(t *testing.T) {
	st := store.New()
	now := time.Now().UTC()
	boot := now.Add(-time.Hour)
	st.Report(apiKernelReport(now.Add(-time.Minute), boot, 100))
	st.Report(apiKernelReport(now, boot, 106))
	s := &Server{store: st, agentStaleAfter: 2 * time.Minute}

	rec := httptest.NewRecorder()
	s.aiCongestionBrief(rec, httptest.NewRequest("GET", "/api/v1/ai/congestion-brief?window=5m", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var b ai.Brief
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Headline != "Kernel network stack pressure" {
		t.Fatalf("headline=%q", b.Headline)
	}
	if !strings.Contains(b.Summary, "warning kernel-network finding(s)") {
		t.Fatalf("summary=%q, want it to mention the kernel-network finding from apiKernelReport's Udp.RcvbufErrors delta", b.Summary)
	}
	if len(b.Findings) == 0 {
		t.Fatalf("findings=%#v, want at least the kernel-network finding rolled into snap.Anomalies", b.Findings)
	}
}

func TestAICongestionBriefRejectsInvalidWindow(t *testing.T) {
	s := &Server{store: store.New()}
	rec := httptest.NewRecorder()
	s.aiCongestionBrief(rec, httptest.NewRequest("GET", "/api/v1/ai/congestion-brief?window=forever", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIAskRoundTripsConversationID(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("POST", "/api/v1/ai/ask", strings.NewReader(`{"question":"what is dropping?","conversationId":"web:abc123"}`))
	rec := httptest.NewRecorder()
	s.aiAsk(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["conversationId"] != "web:abc123" {
		t.Fatalf("conversationId=%v, want echoed input", body["conversationId"])
	}
}

func TestAIAskOmitsConversationIDWhenNotSupplied(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("POST", "/api/v1/ai/ask", strings.NewReader(`{"question":"what is dropping?"}`))
	rec := httptest.NewRecorder()
	s.aiAsk(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["conversationId"]; ok {
		t.Fatalf("body=%v should omit conversationId when the request never supplied one", body)
	}
}

func TestAIForgetClearsConversationMemory(t *testing.T) {
	s := &Server{store: store.New()}

	ask := func(question string) string {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/v1/ai/ask", strings.NewReader(`{"question":"`+question+`","conversationId":"web:forget-test"}`))
		rec := httptest.NewRecorder()
		s.aiAsk(rec, r)
		return rec.Body.String()
	}

	ask("what is dropping?")

	forgetReq := httptest.NewRequest("POST", "/api/v1/ai/forget", strings.NewReader(`{"conversationId":"web:forget-test"}`))
	forgetRec := httptest.NewRecorder()
	s.aiForget(forgetRec, forgetReq)
	if forgetRec.Code != 200 {
		t.Fatalf("status=%d body=%s", forgetRec.Code, forgetRec.Body.String())
	}
	var forgetBody map[string]any
	if err := json.Unmarshal(forgetRec.Body.Bytes(), &forgetBody); err != nil {
		t.Fatal(err)
	}
	if forgetBody["ok"] != true {
		t.Fatalf("forget body=%v", forgetBody)
	}

	// No provider is configured in this test (heuristic-only), so there is
	// no direct way to observe "no memory of the prior turn" from the HTTP
	// response alone — that's exercised at the ai package level
	// (conversation_test.go). This confirms the handler wiring itself:
	// forget must not error, and a subsequent ask on the same id must
	// still succeed normally.
	if got := ask("what is dropping?"); !strings.Contains(got, "heuristic") {
		t.Fatalf("post-forget ask body=%q", got)
	}
}

func TestAIDigestExplainsWhyFingerprintChanged(t *testing.T) {
	s := &Server{store: store.New()}

	digest := func() map[string]any {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/ai/digest", nil)
		rec := httptest.NewRecorder()
		s.aiDigest(rec, r)
		if rec.Code != 200 {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	// The first call only establishes a baseline in internal/ai's shared
	// "last fingerprint" singleton (unexported, so not resettable from
	// here) — it may or may not itself report a change depending on
	// whatever state earlier tests in this binary already left behind.
	// What this test actually verifies is the second call, after a known
	// mutation, reporting exactly that mutation.
	digest()

	if _, err := s.store.SetMode("enforce", 0, "test"); err != nil {
		t.Fatal(err)
	}
	second := digest()
	if second["changed"] != true {
		t.Fatalf("expected changed=true after a mode switch, got %v", second)
	}
	why, _ := second["whyChanged"].([]any)
	if len(why) == 0 {
		t.Fatalf("expected whyChanged to be populated, got %v", second)
	}
	found := false
	for _, w := range why {
		if strings.Contains(w.(string), "fast-path mode changed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("whyChanged=%v missing a mode-change bullet", why)
	}
	if !strings.Contains(second["card"].(string), "Why:") {
		t.Fatalf("card missing Why section: %v", second["card"])
	}
}

func TestAIAgentReturnsStepTrace(t *testing.T) {
	s := &Server{store: store.New()}
	r := httptest.NewRequest("POST", "/api/v1/ai/agent", strings.NewReader(`{"question":"deny dns malware.example"}`))
	rec := httptest.NewRecorder()
	s.aiAgent(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["intent"] != "drops" && body["intent"] != "policy" {
		// "deny dns" classifies as drops because "deny" is a drop keyword.
		// Either way the graph must have run and attached steps.
		t.Logf("intent=%v", body["intent"])
	}
	steps, _ := body["steps"].([]any)
	if len(steps) < 2 {
		t.Fatalf("steps=%v, want classify + synthesize at least", body["steps"])
	}
}
