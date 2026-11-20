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

// TeamsConfig configures a Microsoft Teams Incoming Webhook channel.
type TeamsConfig struct {
	base
	URL string
}

type teamsChannel struct {
	cfg    TeamsConfig
	client *http.Client
}

// NewTeamsChannel validates and returns a Teams Incoming Webhook Channel.
func NewTeamsChannel(cfg TeamsConfig) (Channel, error) {
	cfg.base.applyDefaults()
	if cfg.name == "" {
		return nil, errors.New("teams: name is required")
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("teams: url is required")
	}
	return &teamsChannel{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.timeout},
	}, nil
}

func (c *teamsChannel) Name() string           { return c.cfg.name }
func (c *teamsChannel) MinSeverity() string    { return c.cfg.minSeverity }
func (c *teamsChannel) Timeout() time.Duration { return c.cfg.timeout }
func (c *teamsChannel) MaxAttempts() int       { return c.cfg.maxAttempts }

func (c *teamsChannel) Send(ctx context.Context, ev Event) error {
	if !c.cfg.accepts(ev.Severity) {
		return nil
	}
	color := "Default"
	switch strings.ToLower(ev.Severity) {
	case "critical":
		color = "Attention"
	case "warning":
		color = "Warning"
	}
	// Adaptive Card wrapped for Incoming Webhooks.
	card := map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body": []map[string]any{
						{
							"type":   "TextBlock",
							"size":   "Medium",
							"weight": "Bolder",
							"text":   Title(ev),
							"color":  color,
						},
						{
							"type": "TextBlock",
							"text": Plain(ev),
							"wrap": true,
						},
					},
					"msteams": map[string]any{"width": "Full"},
				},
			},
		},
	}

	body, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("teams %s: marshal: %w", c.cfg.name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("teams %s: request: %w", c.cfg.name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netra-notify/1")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("teams %s: %w", c.cfg.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams %s: status %d", c.cfg.name, resp.StatusCode)
	}
	return nil
}
