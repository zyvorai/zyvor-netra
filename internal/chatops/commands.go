// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package chatops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// pendingAction is the exact method/path/body a confirmation button
// encodes, so the second (block_actions) Slack interaction can execute it
// with no server-side pending-state cache at all — Slack round-trips the
// button's own value back verbatim, and that's the only state this needs.
type pendingAction struct {
	Method, Path, Body, Summary string
}

// pendingActionID is the fixed action_id every confirmation button uses,
// so the block_actions handler always knows how to interpret the value.
const pendingActionID = "netra_chatops_confirm"

func encodePending(p pendingAction) string {
	return p.Method + "|" + p.Path + "|" + base64.StdEncoding.EncodeToString([]byte(p.Body)) + "|" + p.Summary
}

func decodePending(v string) (pendingAction, error) {
	parts := strings.SplitN(v, "|", 4)
	if len(parts) != 4 {
		return pendingAction{}, fmt.Errorf("malformed pending action")
	}
	body, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return pendingAction{}, fmt.Errorf("malformed pending action body")
	}
	return pendingAction{Method: parts[0], Path: parts[1], Body: string(body), Summary: parts[3]}, nil
}

func helpText(allowMutations bool) string {
	var b strings.Builder
	b.WriteString("*Netra ChatOps*\n")
	b.WriteString("`/netra status` – controller status\n")
	b.WriteString("`/netra health` – top network-health anomalies\n")
	b.WriteString("`/netra audit` – recent audit events\n")
	b.WriteString("`/netra scorecard` – 0-100 cluster board\n")
	b.WriteString("`/netra fleet` – agent inventory\n")
	b.WriteString("`/netra talkers` – top destinations\n")
	b.WriteString("`/netra handoff` – on-call pack\n")
	b.WriteString("`/netra baselines` – baseline age\n")
	b.WriteString("`/netra lease` – enforce lease clock\n")
	b.WriteString("`/netra dns` – DNS failures\n")
	b.WriteString("`/netra ask <question>` – ask Netra's AI layer about cluster health (same `/api/v1/ai/agent` graph as the web Ask Netra card; heuristic-only unless NETRA_AI_API_KEY is set). Remembers the last few turns in this channel, per user. Drafts are previews only.\n")
	b.WriteString("`/netra forget` – clear this channel's Ask Netra conversation memory and start fresh\n")
	if allowMutations {
		b.WriteString("`/netra mode observe` / `/netra mode enforce [lease]` – switch fast-path mode (requires confirmation)\n")
		b.WriteString("`/netra capture start NODE [protocol=tcp host=IP port=N duration=60s]` / `/netra capture stop NODE` – packet capture (requires confirmation; captures full packet bytes by default)\n")
	} else {
		b.WriteString("_Mutating commands are disabled on this integration (NETRA_CHATOPS_ALLOW_MUTATIONS is not set)._\n")
	}
	return b.String()
}

// Dispatch parses one slash-command's text and returns either a final reply
// (pending == nil) or a pending mutation requiring a confirmation button
// (reply is the confirmation prompt). allowMutations gates which
// subcommands are even recognized — an unregistered command isn't just
// refused, it doesn't exist, mirroring cmd/netra-mcp/main.go's
// buildServer(c, allowMutations) exactly, not a new per-call-flag
// convention.
//
// conversationKey identifies "this conversation" to Ask Netra's optional
// multi-turn memory (see askCommand/forgetCommand) — every other command
// ignores it. Callers with no natural conversation concept (a one-shot
// CLI invocation) pass "". Slack/Teams compute it from channel+user;
// nothing about it is exposed to the operator beyond /netra forget.
func Dispatch(ctx context.Context, c *Client, allowMutations bool, text, conversationKey string) (reply string, pending *pendingAction) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return helpText(allowMutations), nil
	}
	switch fields[0] {
	case "help":
		return helpText(allowMutations), nil
	case "status":
		return summarize(ctx, c, "GET", "/api/v1/status", nil), nil
	case "health":
		return summarize(ctx, c, "GET", "/api/v1/ebpf/health?limit=5", nil), nil
	case "audit":
		return summarize(ctx, c, "GET", "/api/v1/audit?limit=5", nil), nil
	case "scorecard":
		return summarize(ctx, c, "GET", "/api/v1/scorecard", nil), nil
	case "fleet":
		return summarize(ctx, c, "GET", "/api/v1/fleet", nil), nil
	case "talkers":
		return summarize(ctx, c, "GET", "/api/v1/talkers", nil), nil
	case "handoff":
		return summarize(ctx, c, "GET", "/api/v1/handoff?format=markdown", nil), nil
	case "baselines":
		return summarize(ctx, c, "GET", "/api/v1/baselines", nil), nil
	case "lease":
		return summarize(ctx, c, "GET", "/api/v1/lease", nil), nil
	case "dns":
		return summarize(ctx, c, "GET", "/api/v1/dns/board", nil), nil
	case "ask":
		return askCommand(ctx, c, strings.Join(fields[1:], " "), conversationKey), nil
	case "forget":
		return forgetCommand(ctx, c, conversationKey), nil
	case "mode":
		if !allowMutations {
			return "`/netra mode` is disabled on this integration (NETRA_CHATOPS_ALLOW_MUTATIONS is not set).", nil
		}
		return modeCommand(fields[1:])
	case "capture":
		if !allowMutations {
			return "`/netra capture` is disabled on this integration (NETRA_CHATOPS_ALLOW_MUTATIONS is not set).", nil
		}
		return captureCommand(fields[1:])
	default:
		return fmt.Sprintf("Unknown command %q.\n%s", fields[0], helpText(allowMutations)), nil
	}
}

func modeCommand(args []string) (reply string, pending *pendingAction) {
	if len(args) == 0 {
		return "Usage: `/netra mode observe` or `/netra mode enforce [lease]`, e.g. `/netra mode enforce 15m`.", nil
	}
	mode := strings.ToLower(args[0])
	if mode != "observe" && mode != "enforce" {
		return "mode must be `observe` or `enforce`.", nil
	}
	path := "/api/v1/ebpf/mode"
	summary := fmt.Sprintf("switch fast-path mode to *%s*", mode)
	if mode == "enforce" {
		lease := "15m"
		if len(args) > 1 {
			lease = args[1]
		}
		path += "?lease=" + lease
		summary = fmt.Sprintf("switch fast-path mode to *enforce* for %s (auto-reverts to observe on expiry)", lease)
	}
	body, _ := json.Marshal(map[string]string{"mode": mode})
	p := pendingAction{Method: "PUT", Path: path, Body: string(body), Summary: summary}
	return "Confirm: " + summary + "?", &p
}

// captureCommand mirrors modeCommand's confirm-button shape for packet
// capture start/stop — see internal/api/capture.go's captureStart/
// captureStop for the endpoints this drives. Start requires at least one
// filter field (key=value pairs after the node name), matching the REST
// API's own "no unfiltered captures" rule, checked here too so a bad
// command gets an immediate reply instead of a confirmation button for a
// request the controller will just reject.
func captureCommand(args []string) (reply string, pending *pendingAction) {
	usage := "Usage: `/netra capture start NODE [protocol=tcp host=1.2.3.4 port=443 duration=60s]` or `/netra capture stop NODE`."
	if len(args) < 2 {
		return usage, nil
	}
	node := args[1]
	switch args[0] {
	case "stop":
		summary := "stop the packet capture on *" + node + "*"
		p := pendingAction{Method: "DELETE", Path: "/api/v1/vms/" + node + "/capture", Summary: summary}
		return "Confirm: " + summary + "?", &p
	case "start":
		body := map[string]any{}
		for _, kv := range args[2:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch k {
			case "protocol", "host":
				body[k] = v
			case "port", "snapLen", "maxPps":
				if n, err := strconv.Atoi(v); err == nil {
					body[k] = n
				}
			case "duration":
				if d, err := time.ParseDuration(v); err == nil {
					body["durationSeconds"] = int(d.Seconds())
				}
			}
		}
		if body["protocol"] == nil && body["host"] == nil && body["port"] == nil {
			return "At least one of `protocol=`, `host=`, or `port=` is required — unfiltered captures are not allowed.", nil
		}
		b, _ := json.Marshal(body)
		summary := "start a packet capture on *" + node + "* (captures full packet bytes by default — may include sensitive data)"
		p := pendingAction{Method: "PUT", Path: "/api/v1/vms/" + node + "/capture", Body: string(b), Summary: summary}
		return "Confirm: " + summary + "?", &p
	default:
		return usage, nil
	}
}

// chatAskResponse mirrors only the internal/ai.Brief fields askCommand
// renders — deliberately a local type, not an import of internal/ai,
// preserving this package's existing boundary (see client.go's package
// doc comment): netrad is a black-box HTTP API to chatops, never a Go
// dependency.
type chatAskResponse struct {
	Headline string `json:"headline"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Findings []struct {
		Kind    string `json:"kind,omitempty"`
		Subject string `json:"subject,omitempty"`
		Message string `json:"message"`
	} `json:"findings"`
	NextSteps []string `json:"nextSteps"`
	Engine    string   `json:"engine"`
}

// chatAgentResponse is POST /api/v1/ai/agent. Brief is nested; we also
// accept the older flat /ai/ask shape so a mis-routed mock still renders.
type chatAgentResponse struct {
	chatAskResponse
	Brief  chatAskResponse `json:"brief"`
	Intent string          `json:"intent"`
	Draft  *struct {
		Understood bool   `json:"understood"`
		Summary    string `json:"summary"`
		CLI        string `json:"cli"`
		Note       string `json:"note"`
	} `json:"draft"`
	Steps []struct {
		Node   string `json:"node"`
		Detail string `json:"detail"`
	} `json:"steps"`
}

func (r chatAgentResponse) brief() chatAskResponse {
	if r.Brief.Headline != "" || r.Brief.Summary != "" {
		return r.Brief
	}
	return r.chatAskResponse
}

// askCommand answers a free-text question via POST /api/v1/ai/agent —
// the same in-process NL graph the web Ask Netra card uses.
// Heuristic-only unless NETRA_AI_API_KEY is configured on the controller,
// same fallback as every other internal/ai consumer. Read-only: no
// confirmation step, no allowMutations gate, empty actor (nothing to
// audit-attribute for a question), matching status/health/audit's
// existing unaudited-read shape.
//
// conversationKey, when non-empty, is sent as the request's conversationId
// so this channel+user's prior turns (internal/ai's short-lived,
// bounded memory) can resolve references like "that" or "the second one" —
// see forgetCommand for clearing it.
func askCommand(ctx context.Context, c *Client, question, conversationKey string) string {
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	reqBody := map[string]string{"question": question}
	if conversationKey != "" {
		reqBody["conversationId"] = conversationKey
	}
	body, _ := json.Marshal(reqBody)
	out, status, err := c.Do(callCtx, "POST", "/api/v1/ai/agent", body, "")
	if err != nil {
		return fmt.Sprintf("Request to /api/v1/ai/agent failed: %v", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Sprintf("/api/v1/ai/agent returned HTTP %d:\n```%s```", status, truncate(string(out), 800))
	}
	var agent chatAgentResponse
	if err := json.Unmarshal(out, &agent); err != nil {
		return fmt.Sprintf("Could not parse the AI response: %v", err)
	}
	brief := agent.brief()

	var b strings.Builder
	fmt.Fprintf(&b, "*%s* _(%s)_\n", brief.Headline, brief.Severity)
	if brief.Summary != "" {
		fmt.Fprintf(&b, "%s\n", brief.Summary)
	}
	for i, f := range brief.Findings {
		if i >= 3 {
			break
		}
		subject := f.Subject
		if f.Kind != "" && subject != "" {
			subject = f.Kind + " · " + subject
		} else if f.Kind != "" {
			subject = f.Kind
		}
		if subject != "" {
			fmt.Fprintf(&b, "• *%s*: %s\n", subject, f.Message)
		} else {
			fmt.Fprintf(&b, "• %s\n", f.Message)
		}
	}
	for _, step := range brief.NextSteps {
		fmt.Fprintf(&b, "→ %s\n", step)
	}
	if agent.Draft != nil && agent.Draft.Understood {
		fmt.Fprintf(&b, "\n_Rule preview (not applied):_ %s\n", agent.Draft.Summary)
		if agent.Draft.CLI != "" {
			fmt.Fprintf(&b, "`%s`\n", agent.Draft.CLI)
		}
	}
	if brief.Engine != "" {
		fmt.Fprintf(&b, "_engine: %s_", brief.Engine)
	}
	return truncate(b.String(), 2800)
}

// forgetCommand clears this channel+user's Ask Netra conversation memory
// via POST /api/v1/ai/forget — the only way internal/chatops ever touches
// that state, same "netrad is a black-box HTTP API" boundary askCommand
// follows. A conversationKey of "" means this integration never computed
// one (Slack/Teams could not identify the channel or user), so there is
// nothing to clear.
func forgetCommand(ctx context.Context, c *Client, conversationKey string) string {
	if conversationKey == "" {
		return "Nothing to forget — this integration doesn't have a conversation to reset."
	}
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"conversationId": conversationKey})
	_, status, err := c.Do(callCtx, "POST", "/api/v1/ai/forget", body, "")
	if err != nil {
		return fmt.Sprintf("Request to /api/v1/ai/forget failed: %v", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Sprintf("/api/v1/ai/forget returned HTTP %d", status)
	}
	return "Cleared. `/netra ask` starts a fresh conversation from here."
}

// summarize calls path and renders a short, Slack-message-sized summary of
// the response — a compact indented JSON snippet capped well under Slack's
// per-block character limit, not a hand-parsed field-by-field rendering,
// so this stays correct as the underlying endpoints' response shapes grow.
func summarize(ctx context.Context, c *Client, method, path string, body []byte) string {
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, status, err := c.Do(callCtx, method, path, body, "")
	if err != nil {
		return fmt.Sprintf("Request to %s failed: %v", path, err)
	}
	if status < 200 || status >= 300 {
		return fmt.Sprintf("%s returned HTTP %d:\n```%s```", path, status, truncate(string(out), 800))
	}
	pretty := prettyJSON(out)
	return fmt.Sprintf("```%s```", truncate(pretty, 2800))
}

func prettyJSON(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n… truncated"
}
