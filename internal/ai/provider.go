// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultTimeout = 20 * time.Second
	maxBody        = 1 << 20
)

// Provider is an optional OpenAI-compatible chat-completions client.
// It is off unless NETRA_AI_API_KEY is set. The default base URL is
// https://api.openai.com/v1 so any compatible gateway works by pointing
// NETRA_AI_BASE_URL at it.
type Provider struct {
	BaseURL    string
	APIKey     string
	Model      string
	HTTPClient *http.Client
}

// ProviderFromEnv reads the optional LLM settings. A nil return means
// heuristic-only mode — the supported production default.
func ProviderFromEnv() *Provider {
	key := strings.TrimSpace(os.Getenv("NETRA_AI_API_KEY"))
	if key == "" {
		return nil
	}
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("NETRA_AI_BASE_URL")), "/")
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	model := strings.TrimSpace(os.Getenv("NETRA_AI_MODEL"))
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &Provider{
		BaseURL:    base,
		APIKey:     key,
		Model:      model,
		HTTPClient: &http.Client{Timeout: defaultTimeout},
	}
}

// Enabled reports whether a rewrite call would be attempted.
func (p *Provider) Enabled() bool {
	return p != nil && strings.TrimSpace(p.APIKey) != "" && strings.TrimSpace(p.BaseURL) != ""
}

// CurrentStatus is the public /api/v1/ai/status payload.
func CurrentStatus() Status {
	p := ProviderFromEnv()
	if p == nil {
		return Status{Enabled: false, HeuristicOnly: true, Mutations: "never — AI endpoints are read-only"}
	}
	return Status{
		Enabled:       true,
		Provider:      p.BaseURL,
		Model:         p.Model,
		HeuristicOnly: false,
		Mutations:     "never — AI endpoints are read-only",
	}
}

type chatRequest struct {
	Model       string        `json:"model"`
	Temperature float64       `json:"temperature"`
	Messages    []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Rewrite asks the provider to turn the snapshot + heuristic brief into
// a short operator paragraph. The system prompt forbids mutations,
// secrets, and invented counters.
//
// history is the conversation's prior turns, oldest first (nil for a
// stateless call or a fresh conversation) — see conversation.go. It is
// included only to help resolve references like "that" or "the second
// one"; the system prompt makes explicit that it is not new cluster data.
func (p *Provider) Rewrite(ctx context.Context, snap Snapshot, brief Brief, question string, history []Turn) (string, error) {
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return "", err
	}
	sys := strings.Join([]string{
		"You are Netra's read-only network observability assistant.",
		"Answer only from the JSON snapshot. Never invent counters, IPs, workloads, or CVE IDs.",
		"Never recommend running enforce mode without an explicit human lease renewal.",
		"Never request or echo secrets, API keys, packet payloads, argv, or Kubernetes Secret contents.",
		"Netra does not collect application payloads; do not pretend it does.",
		"Prefer concrete next steps that map to existing Netra pages or netractl/MCP tools.",
		"Prior conversation turns, if present, are given only to resolve references such as \"that\" or \"the second one\" — they are not new information about the cluster; the snapshot JSON is always the sole source of truth for current counters.",
		"Keep the answer under 180 words.",
	}, " ")
	user := "Question: " + strings.TrimSpace(question) + "\n\nHeuristic brief:\n" + brief.Headline + "\n" + brief.Summary + historyBlock(history) + "\n\nSnapshot JSON:\n" + string(snapJSON)
	return p.RewriteText(ctx, sys, user)
}

func historyBlock(history []Turn) string {
	if len(history) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\nPrior turns in this conversation (oldest first, reference-resolution only):\n")
	for _, t := range history {
		b.WriteString("- Q: " + t.Question + "\n  A: " + t.Summary + "\n")
	}
	return b.String()
}

// RewriteText is the Snapshot-agnostic primitive Rewrite builds on: given a
// system prompt and a user prompt, ask the provider for a short completion.
// Other deterministic-then-optionally-rewritten features (e.g.
// internal/timeline's incident timeline) call this directly instead of
// forcing their own data into a Snapshot just to reuse Rewrite.
func (p *Provider) RewriteText(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if !p.Enabled() {
		return "", fmt.Errorf("ai provider disabled")
	}
	body, err := json.Marshal(chatRequest{
		Model:       p.Model,
		Temperature: 0.2,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	})
	if err != nil {
		return "", err
	}

	url := p.BaseURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("ai provider: decode: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return "", fmt.Errorf("ai provider: %s", parsed.Error.Message)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ai provider: HTTP %d", resp.StatusCode)
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("ai provider: empty completion")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}
