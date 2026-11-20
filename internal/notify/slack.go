// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SlackConfig configures Slack Incoming Webhook or Web API posting.
type SlackConfig struct {
	base
	// Mode is "incoming" (default) or "api".
	Mode    string
	URL     string // Incoming Webhook URL
	Token   string // Bot token for mode=api
	Channel string // Channel for mode=api
}

type slackChannel struct {
	cfg    SlackConfig
	client *http.Client
}

// NewSlackChannel validates and returns a Slack Channel.
func NewSlackChannel(cfg SlackConfig) (Channel, error) {
	cfg.base.applyDefaults()
	if cfg.name == "" {
		return nil, errors.New("slack: name is required")
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "incoming"
	}
	cfg.Mode = mode
	switch mode {
	case "incoming":
		if strings.TrimSpace(cfg.URL) == "" {
			return nil, errors.New("slack: url is required for mode=incoming")
		}
	case "api":
		if strings.TrimSpace(cfg.Token) == "" {
			return nil, errors.New("slack: token is required for mode=api")
		}
		if strings.TrimSpace(cfg.Channel) == "" {
			return nil, errors.New("slack: channel is required for mode=api")
		}
	default:
		return nil, fmt.Errorf("slack: unknown mode %q", cfg.Mode)
	}
	return &slackChannel{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.timeout},
	}, nil
}

func (c *slackChannel) Name() string           { return c.cfg.name }
func (c *slackChannel) MinSeverity() string    { return c.cfg.minSeverity }
func (c *slackChannel) Timeout() time.Duration { return c.cfg.timeout }
func (c *slackChannel) MaxAttempts() int       { return c.cfg.maxAttempts }

func (c *slackChannel) Send(ctx context.Context, ev Event) error {
	if !c.cfg.accepts(ev.Severity) {
		return nil
	}
	text := ev.Text
	if text == "" {
		text = Plain(ev)
	}
	payload := map[string]any{
		"text": text,
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*%s*\n%s", Title(ev), ev.Message),
				},
			},
		},
	}
	if c.cfg.Mode == "api" {
		payload["channel"] = c.cfg.Channel
		return c.postJSON(ctx, "https://slack.com/api/chat.postMessage", payload, c.cfg.Token)
	}
	return c.postJSON(ctx, c.cfg.URL, payload, "")
}

func (c *slackChannel) postJSON(ctx context.Context, url string, payload map[string]any, bearer string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack %s: marshal: %w", c.cfg.name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack %s: request: %w", c.cfg.name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netra-notify/1")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack %s: %w", c.cfg.name, err)
	}
	defer resp.Body.Close()
	if c.cfg.Mode == "api" {
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode >= 300 || !out.OK {
			errMsg := out.Error
			if errMsg == "" {
				errMsg = fmt.Sprintf("status %d", resp.StatusCode)
			}
			return fmt.Errorf("slack %s: %s", c.cfg.name, errMsg)
		}
		return nil
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack %s: status %d", c.cfg.name, resp.StatusCode)
	}
	return nil
}
