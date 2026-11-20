// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// teamsActivity is the subset of a Bot Framework Activity this integration
// reads — the inbound webhook body for every user message. Fields Netra
// never uses (channelId, serviceUrl, timestamp, …) are left unparsed.
type teamsActivity struct {
	Type string `json:"type"`
	Text string `json:"text"`
	From struct {
		ID string `json:"id"`
	} `json:"from"`
	Recipient struct {
		ID string `json:"id"`
	} `json:"recipient"`
	Conversation struct {
		ID string `json:"id"`
	} `json:"conversation"`
	Entities []struct {
		Type      string `json:"type"`
		Text      string `json:"text"`
		Mentioned struct {
			ID string `json:"id"`
		} `json:"mentioned"`
	} `json:"entities"`
}

// teamsConfirmPrefix is what a user types to approve a pending mutation —
// Teams has no server-pushed confirmation button in this v1 (see
// TeamsConfig's doc comment), so the pending action's own encoded token
// travels in a second typed message instead.
const teamsConfirmPrefix = "/netra confirm "

// TeamsConfig wires one Teams ChatOps HTTP handler.
type TeamsConfig struct {
	// AppID is NETRA_CHATOPS_TEAMS_APP_ID — the Azure Bot Service app
	// registration's Microsoft App ID, required as the inbound JWT's "aud"
	// claim. Required; NewTeamsHandler panics without one, mirroring
	// NewHandler's SigningSecret requirement.
	AppID string
	// AllowMutations is NETRA_CHATOPS_ALLOW_MUTATIONS — the same flag
	// Slack's Config uses, shared across both providers since it gates
	// Dispatch itself, not anything provider-specific.
	AllowMutations bool
	// Client makes the actual outbound calls back into netrad's own API.
	Client *Client
	// Verifier is overridable for tests; defaults to NewTeamsVerifier(AppID).
	Verifier *TeamsVerifier
}

// NewTeamsHandler returns the POST /chatops/teams handler: registered
// outside the controller's normal bearer-token auth (Teams can't send that
// header either) but on the same mux internal/api/server.go promotes
// behind ha.Gate, so standby replicas correctly 503 it too.
//
// Slack's confirmation flow round-trips a Block Kit button click
// (block_actions); Teams' equivalent is an Adaptive Card Action.Submit,
// which arrives as a separate "invoke" activity requiring its own
// Connector API reply shape — meaningfully more machinery than Slack's
// "reply directly in the HTTP response" model. For v1, Teams instead asks
// the user to send a second message, "/netra confirm <token>", reusing
// encodePending/decodePending exactly as Slack's button value does.
func NewTeamsHandler(cfg TeamsConfig) http.Handler {
	if cfg.AppID == "" {
		panic("chatops: NewTeamsHandler requires a non-empty AppID")
	}
	if cfg.Verifier == nil {
		cfg.Verifier = NewTeamsVerifier(cfg.AppID)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || token == r.Header.Get("Authorization") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if err := cfg.Verifier.Verify(token); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var activity teamsActivity
		if err := json.Unmarshal(body, &activity); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Bot Framework sends non-message activities too (conversationUpdate
		// on install, typing, …) — nothing to reply to those with.
		if activity.Type != "message" {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeTeamsReply(w, dispatchTeamsActivity(r.Context(), cfg, activity))
	})
}

// dispatchTeamsActivity cleans the inbound text and routes it to either the
// confirm flow or Dispatch, returning the reply text.
func dispatchTeamsActivity(ctx context.Context, cfg TeamsConfig, activity teamsActivity) string {
	text := stripTeamsMention(activity)
	if strings.HasPrefix(text, teamsConfirmPrefix) {
		return confirmTeamsPending(ctx, cfg.Client, strings.TrimSpace(strings.TrimPrefix(text, teamsConfirmPrefix)), activity.From.ID)
	}
	cmdText := strings.TrimSpace(strings.TrimPrefix(text, "/netra"))
	reply, pending := Dispatch(ctx, cfg.Client, cfg.AllowMutations, cmdText, teamsConversationKey(activity))
	if pending == nil {
		return reply
	}
	return reply + "\nReply `" + teamsConfirmPrefix + encodePending(*pending) + "` to proceed."
}

// teamsConversationKey mirrors slackConversationKey's (channel, user) pair
// with Teams' own identifiers: a Bot Framework conversation id (channel-
// equivalent) plus the sender's id. Missing either degrades to "" — same
// as any caller that never opts into Ask Netra's multi-turn memory.
func teamsConversationKey(activity teamsActivity) string {
	if activity.Conversation.ID == "" || activity.From.ID == "" {
		return ""
	}
	return "teams:" + activity.Conversation.ID + ":" + activity.From.ID
}

// confirmTeamsPending decodes and executes a pending action, tagging the
// actor "chatops-teams:<from-id>" — mirroring Slack's "chatops:<user-id>"
// convention exactly but with a distinct prefix, so the two providers stay
// distinguishable in the audit log.
func confirmTeamsPending(ctx context.Context, c *Client, tokenValue, fromID string) string {
	p, err := decodePending(tokenValue)
	if err != nil {
		return "This confirmation has expired or is malformed; re-run the slash command."
	}
	if fromID == "" {
		return "Could not identify the confirming Teams user; refusing to apply."
	}
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, status, err := c.Do(callCtx, p.Method, p.Path, []byte(p.Body), "chatops-teams:"+fromID)
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Sprintf("%s: HTTP %d\n%s", p.Summary, status, truncate(string(out), 800))
	}
	return fmt.Sprintf("Done by %s: %s", fromID, p.Summary)
}

// stripTeamsMention removes a leading @mention of the bot from activity's
// text. Teams wraps a mention as "<at>Name</at>" in Text and carries the
// matching detail in Entities (type "mention", with Mentioned.ID equal to
// Recipient.ID for a self-mention) — stripped from there rather than by
// fragile prefix matching against a display name Netra doesn't know ahead
// of time. If no matching entity is found (some clients omit Entities
// entirely), a plain "<at>...</at>" prefix strip is the fallback.
func stripTeamsMention(activity teamsActivity) string {
	text := activity.Text
	sawMentionEntity := false
	for _, e := range activity.Entities {
		if e.Type != "mention" || e.Text == "" {
			continue
		}
		sawMentionEntity = true
		if activity.Recipient.ID != "" && e.Mentioned.ID != activity.Recipient.ID {
			continue
		}
		text = strings.Replace(text, e.Text, "", 1)
	}
	text = strings.TrimSpace(text)
	// Only fall back to naive prefix stripping when Entities gave no usable
	// mention info at all — if a mention entity was present but didn't
	// match this recipient (someone else was @mentioned), trust that and
	// leave the text alone rather than blindly stripping any "<at>...</at>".
	if !sawMentionEntity && strings.HasPrefix(text, "<at>") {
		if end := strings.Index(text, "</at>"); end >= 0 {
			text = strings.TrimSpace(text[end+len("</at>"):])
		}
	}
	return text
}

// writeTeamsReply writes a synchronous Activity reply in the HTTP response
// body — Bot Framework accepts this directly for a simple text turn, the
// same "reply in the HTTP response" simplicity Slack's writeMessage uses,
// with no outbound Connector API call needed for v1.
func writeTeamsReply(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "message", "text": text})
}
