// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Config wires one chatops HTTP handler.
type Config struct {
	// SigningSecret is NETRA_CHATOPS_SIGNING_SECRET — the Slack app's own
	// signing secret, used only to verify inbound requests actually came
	// from Slack. Required; NewHandler panics without one, since a handler
	// with no way to verify signatures would accept forged requests.
	SigningSecret string
	// AllowMutations is NETRA_CHATOPS_ALLOW_MUTATIONS — gates which
	// commands Dispatch even recognizes, not just whether it executes them.
	AllowMutations bool
	// Client makes the actual outbound calls back into netrad's own API.
	Client *Client
	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time
}

// NewHandler returns the POST /chatops/slack handler: registered outside
// the controller's normal bearer-token auth (Slack can't send that header)
// but still mounted on the same mux internal/api/server.go promotes behind
// ha.Gate, so standby replicas correctly 503 it too, with no separate
// wiring needed for that.
func NewHandler(cfg Config) http.Handler {
	if cfg.SigningSecret == "" {
		panic("chatops: NewHandler requires a non-empty SigningSecret")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := VerifySlackSignature(cfg.SigningSecret, r.Header.Get("X-Slack-Request-Timestamp"), body, r.Header.Get("X-Slack-Signature"), cfg.Now()); err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if payload := form.Get("payload"); payload != "" {
			handleInteraction(w, r.Context(), cfg, payload)
			return
		}
		handleSlashCommand(w, r.Context(), cfg, form)
	})
}

func handleSlashCommand(w http.ResponseWriter, ctx context.Context, cfg Config, form url.Values) {
	reply, pending := Dispatch(ctx, cfg.Client, cfg.AllowMutations, form.Get("text"), slackConversationKey(form))
	if pending == nil {
		writeMessage(w, reply, nil)
		return
	}
	writeMessage(w, reply, confirmBlocks(*pending))
}

// slackConversationKey identifies "this conversation" for Ask Netra's
// multi-turn memory as the (channel, user) pair Slack's slash-command POST
// already carries — no new state to track, and no more than any other
// Slack app already learns about who ran the command and where. Missing
// either field (shouldn't happen for a real slash command) degrades to ""
// — the same as any caller that never opts in.
func slackConversationKey(form url.Values) string {
	channel := form.Get("channel_id")
	user := form.Get("user_id")
	if channel == "" || user == "" {
		return ""
	}
	return "slack:" + channel + ":" + user
}

func handleInteraction(w http.ResponseWriter, ctx context.Context, cfg Config, payloadJSON string) {
	var payload struct {
		Type string `json:"type"`
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if payload.Type != "block_actions" || len(payload.Actions) == 0 || payload.Actions[0].ActionID != pendingActionID {
		writeMessage(w, "Unrecognized interaction.", nil)
		return
	}
	p, err := decodePending(payload.Actions[0].Value)
	if err != nil {
		writeMessage(w, "This confirmation has expired or is malformed; re-run the slash command.", nil)
		return
	}
	if payload.User.ID == "" {
		writeMessage(w, "Could not identify the confirming Slack user; refusing to apply.", nil)
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, status, err := cfg.Client.Do(callCtx, p.Method, p.Path, []byte(p.Body), "chatops:"+payload.User.ID)
	if err != nil {
		writeMessage(w, fmt.Sprintf("Request failed: %v", err), nil)
		return
	}
	if status < 200 || status >= 300 {
		writeMessage(w, fmt.Sprintf("%s: HTTP %d\n```%s```", p.Summary, status, truncate(string(out), 800)), nil)
		return
	}
	writeMessage(w, fmt.Sprintf("Done by <@%s>: %s", payload.User.ID, p.Summary), nil)
}

// confirmBlocks builds the single-button Slack Block Kit confirmation
// prompt for a pending mutation. "enforce" gets Slack's "danger" button
// style as a visual cue; every other mutating command gets the plain
// "primary" style.
func confirmBlocks(p pendingAction) []map[string]any {
	style := "primary"
	if containsEnforce(p.Body) {
		style = "danger"
	}
	return []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "Confirm: " + p.Summary + "?"}},
		{"type": "actions", "elements": []map[string]any{
			{
				"type":      "button",
				"text":      map[string]any{"type": "plain_text", "text": "Confirm"},
				"action_id": pendingActionID,
				"value":     encodePending(p),
				"style":     style,
			},
		}},
	}
}

func containsEnforce(body string) bool {
	var v struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal([]byte(body), &v)
	return v.Mode == "enforce"
}

func writeMessage(w http.ResponseWriter, text string, blocks []map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	msg := map[string]any{"response_type": "ephemeral", "replace_original": true}
	if len(blocks) > 0 {
		msg["blocks"] = blocks
	} else {
		msg["text"] = text
	}
	_ = json.NewEncoder(w).Encode(msg)
}
