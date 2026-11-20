// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"fmt"
	"testing"
	"time"
)

// resetConversations clears package state and restores nowFn, so tests
// don't leak conversations or a stubbed clock into each other.
func resetConversations(t *testing.T) {
	t.Helper()
	convMu.Lock()
	convStore = map[string]*conversation{}
	convMu.Unlock()
	nowFn = time.Now
	t.Cleanup(func() {
		convMu.Lock()
		convStore = map[string]*conversation{}
		convMu.Unlock()
		nowFn = time.Now
	})
}

func TestConversationHistoryRoundTrip(t *testing.T) {
	resetConversations(t)
	if h := conversationHistory("c1"); h != nil {
		t.Fatalf("history for unknown id=%v, want nil", h)
	}
	recordConversationTurn("c1", Turn{Question: "q1", Summary: "a1"})
	recordConversationTurn("c1", Turn{Question: "q2", Summary: "a2"})
	h := conversationHistory("c1")
	if len(h) != 2 || h[0].Question != "q1" || h[1].Question != "q2" {
		t.Fatalf("history=%#v", h)
	}
	// conversationHistory returns a copy — mutating it must not affect
	// the store.
	h[0].Question = "mutated"
	if got := conversationHistory("c1"); got[0].Question != "q1" {
		t.Fatalf("store mutated through returned slice: %#v", got)
	}
}

func TestConversationHistoryIgnoresEmptyID(t *testing.T) {
	resetConversations(t)
	recordConversationTurn("", Turn{Question: "q", Summary: "a"})
	if h := conversationHistory(""); h != nil {
		t.Fatalf("history for empty id=%v, want nil", h)
	}
	if len(convStore) != 0 {
		t.Fatalf("empty id must never be stored, store=%#v", convStore)
	}
}

func TestConversationTurnCapIsARing(t *testing.T) {
	resetConversations(t)
	for i := 0; i < maxConversationTurns+3; i++ {
		recordConversationTurn("c1", Turn{Question: fmt.Sprintf("q%d", i)})
	}
	h := conversationHistory("c1")
	if len(h) != maxConversationTurns {
		t.Fatalf("len(history)=%d, want %d", len(h), maxConversationTurns)
	}
	// Oldest turns (q0, q1, q2) must have been evicted first.
	if h[0].Question != "q3" {
		t.Fatalf("oldest retained turn=%q, want q3", h[0].Question)
	}
	last := fmt.Sprintf("q%d", maxConversationTurns+2)
	if h[len(h)-1].Question != last {
		t.Fatalf("newest retained turn=%q, want %q", h[len(h)-1].Question, last)
	}
}

func TestConversationTurnsAreClipped(t *testing.T) {
	resetConversations(t)
	long := make([]byte, turnClipRunes*2)
	for i := range long {
		long[i] = 'x'
	}
	recordConversationTurn("c1", Turn{Question: string(long), Summary: string(long)})
	h := conversationHistory("c1")
	if len(h) != 1 || len([]rune(h[0].Question)) != turnClipRunes || len([]rune(h[0].Summary)) != turnClipRunes {
		t.Fatalf("turn not clipped to %d runes: len(question)=%d len(summary)=%d", turnClipRunes, len([]rune(h[0].Question)), len([]rune(h[0].Summary)))
	}
}

func TestConversationTTLExpiry(t *testing.T) {
	resetConversations(t)
	base := time.Now()
	nowFn = func() time.Time { return base }
	recordConversationTurn("c1", Turn{Question: "q1"})
	if h := conversationHistory("c1"); len(h) != 1 {
		t.Fatalf("history before expiry=%v", h)
	}
	nowFn = func() time.Time { return base.Add(conversationTTL + time.Minute) }
	if h := conversationHistory("c1"); h != nil {
		t.Fatalf("history after TTL expiry=%v, want nil", h)
	}
}

func TestConversationTTLExpirySweepsOnWrite(t *testing.T) {
	resetConversations(t)
	base := time.Now()
	nowFn = func() time.Time { return base }
	recordConversationTurn("stale", Turn{Question: "q1"})
	nowFn = func() time.Time { return base.Add(conversationTTL + time.Minute) }
	recordConversationTurn("fresh", Turn{Question: "q2"})

	convMu.Lock()
	_, staleStillPresent := convStore["stale"]
	convMu.Unlock()
	if staleStillPresent {
		t.Fatal("expired conversation should have been swept on the next write")
	}
	if h := conversationHistory("fresh"); len(h) != 1 {
		t.Fatalf("fresh conversation history=%v", h)
	}
}

func TestConversationGlobalCapDegradesGracefully(t *testing.T) {
	resetConversations(t)
	for i := 0; i < maxConversations; i++ {
		recordConversationTurn(fmt.Sprintf("c%d", i), Turn{Question: "q"})
	}
	if len(convStore) != maxConversations {
		t.Fatalf("len(convStore)=%d, want %d", len(convStore), maxConversations)
	}
	// One more distinct conversation over the cap must be silently
	// dropped, not grow the store or panic.
	recordConversationTurn("overflow", Turn{Question: "q"})
	if len(convStore) != maxConversations {
		t.Fatalf("len(convStore) after overflow=%d, want unchanged %d", len(convStore), maxConversations)
	}
	if h := conversationHistory("overflow"); h != nil {
		t.Fatalf("overflow conversation history=%v, want nil (never stored)", h)
	}
}

func TestClearConversation(t *testing.T) {
	resetConversations(t)
	recordConversationTurn("c1", Turn{Question: "q1"})
	ClearConversation("c1")
	if h := conversationHistory("c1"); h != nil {
		t.Fatalf("history after ClearConversation=%v, want nil", h)
	}
	// Clearing an unknown or empty id must not panic.
	ClearConversation("unknown")
	ClearConversation("")
}
