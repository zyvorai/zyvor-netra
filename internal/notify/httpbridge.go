// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HTTPBridgeConfig configures a generic typed HTTP bridge.
type HTTPBridgeConfig struct {
	base
	URL         string
	Secret      string
	Headers     map[string]string
	ChannelHint string // sms|whatsapp|email|other
}

type httpBridgeChannel struct {
	cfg    HTTPBridgeConfig
	client *http.Client
}

// BridgeEnvelope is the JSON body POSTed to an httpbridge URL.
type BridgeEnvelope struct {
	ChannelHint string `json:"channelHint"`
	Event       Event  `json:"event"`
}

// NewHTTPBridgeChannel validates and returns an HTTP bridge Channel.
func NewHTTPBridgeChannel(cfg HTTPBridgeConfig) (Channel, error) {
	cfg.base.applyDefaults()
	if cfg.name == "" {
		return nil, errors.New("httpbridge: name is required")
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("httpbridge: url is required")
	}
	if cfg.ChannelHint == "" {
		cfg.ChannelHint = "other"
	}
	return &httpBridgeChannel{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.timeout},
	}, nil
}

func (c *httpBridgeChannel) Name() string           { return c.cfg.name }
func (c *httpBridgeChannel) MinSeverity() string    { return c.cfg.minSeverity }
func (c *httpBridgeChannel) Timeout() time.Duration { return c.cfg.timeout }
func (c *httpBridgeChannel) MaxAttempts() int       { return c.cfg.maxAttempts }

func (c *httpBridgeChannel) Send(ctx context.Context, ev Event) error {
	if !c.cfg.accepts(ev.Severity) {
		return nil
	}
	env := BridgeEnvelope{ChannelHint: c.cfg.ChannelHint, Event: ev}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("httpbridge %s: marshal: %w", c.cfg.name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("httpbridge %s: request: %w", c.cfg.name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netra-notify/1")
	if c.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(c.cfg.Secret))
		mac.Write(body)
		req.Header.Set("X-Netra-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("httpbridge %s: %w", c.cfg.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("httpbridge %s: status %d", c.cfg.name, resp.StatusCode)
	}
	return nil
}
