// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"sync"
	"time"
)

const (
	// maxConversationTurns bounds how many prior turns a conversation
	// keeps — a ring, oldest dropped first — so the history block added
	// to the LLM prompt never grows unbounded.
	maxConversationTurns = 6
	// conversationTTL is the idle window after which a conversation is
	// swept: no explicit close/logout exists on any surface (web tab,
	// Slack channel, Teams channel) that calls this, so time is the only
	// signal.
	conversationTTL = 30 * time.Minute
	// maxConversations is a soft cap on how many live (non-expired)
	// conversations this process tracks at once. Callers are already
	// authenticated the same as any other /api/v1 route, so this guards
	// against unbounded memory growth rather than a hostile actor.
	maxConversations = 2000
	// turnClipRunes bounds how much of a question/summary is stored per
	// turn, so a very long question can't grow the prompt sent to the
	// provider unboundedly across turns.
	turnClipRunes = 240
)

// Turn is one already-answered exchange, kept only so a later question in
// the same conversation can resolve references like "that" or "the second
// one" — never the raw snapshot, never anything not already shown to the
// operator.
type Turn struct {
	Question string
	Summary  string
}

type conversation struct {
	turns      []Turn
	lastAccess time.Time
}

var (
	// nowFn is overridable in tests so TTL expiry doesn't require real
	// sleeps, mirroring chatops.Config's Now field.
	nowFn = time.Now

	convMu    sync.Mutex
	convStore = map[string]*conversation{}
)

// conversationHistory returns a copy of id's stored turns, oldest first.
// An empty, unknown, or expired id returns nil — indistinguishable from a
// brand-new conversation to every caller.
func conversationHistory(id string) []Turn {
	if id == "" {
		return nil
	}
	convMu.Lock()
	defer convMu.Unlock()
	c, ok := convStore[id]
	if !ok || nowFn().Sub(c.lastAccess) > conversationTTL {
		return nil
	}
	out := make([]Turn, len(c.turns))
	copy(out, c.turns)
	return out
}

// recordConversationTurn appends t to id's history, evicting the oldest
// turn once maxConversationTurns is exceeded. It opportunistically sweeps
// expired conversations first, and once maxConversations live
// conversations already exist, silently drops the turn instead of growing
// the store further or erroring the caller's request.
func recordConversationTurn(id string, t Turn) {
	if id == "" {
		return
	}
	t.Question = clipRunes(t.Question, turnClipRunes)
	t.Summary = clipRunes(t.Summary, turnClipRunes)

	convMu.Lock()
	defer convMu.Unlock()
	now := nowFn()
	sweepExpiredLocked(now)

	c, ok := convStore[id]
	if !ok {
		if len(convStore) >= maxConversations {
			return
		}
		c = &conversation{}
		convStore[id] = c
	}
	c.turns = append(c.turns, t)
	if len(c.turns) > maxConversationTurns {
		c.turns = c.turns[len(c.turns)-maxConversationTurns:]
	}
	c.lastAccess = now
}

// ClearConversation drops any stored history for id — used by
// POST /api/v1/ai/forget (and, through it, ChatOps's /netra forget) so an
// operator can start over deterministically instead of waiting out the
// TTL.
func ClearConversation(id string) {
	if id == "" {
		return
	}
	convMu.Lock()
	defer convMu.Unlock()
	delete(convStore, id)
}

func sweepExpiredLocked(now time.Time) {
	for id, c := range convStore {
		if now.Sub(c.lastAccess) > conversationTTL {
			delete(convStore, id)
		}
	}
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
