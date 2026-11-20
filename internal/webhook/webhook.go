// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package webhook delivers structured alert events to HTTP endpoints. A
// Dispatcher fans events out to one or more Sinks; delivery is
// at-least-once-best-effort, not exactly-once, and a full queue drops
// events rather than blocking the publisher.
package webhook

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
	"time"
)

// Event is the payload delivered to sinks. Its fields mirror
// models.NetworkHealthAnomaly 1:1 (Kind/Severity/Subject/Message/Value) so
// internal/alert can translate without this package needing to import
// internal/models. Source names which producer package emitted the event
// (e.g. "health", "pathdiag", "dropdiag").
type Event struct {
	Source    string    `json:"source"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	Subject   string    `json:"subject"`
	Message   string    `json:"message"`
	Value     float64   `json:"value,omitempty"`
	Node      string    `json:"node,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	// Optional AI digest fields. Empty on classic health/path/drop events.
	Fingerprint string `json:"fingerprint,omitempty"`
	Card        string `json:"card,omitempty"`
	// Text is a Slack incoming-webhook compatible body field. Set on
	// digest events so hooks.slack.com renders the card instead of raw JSON keys.
	Text string `json:"text,omitempty"`
}

// severityRank orders "info" < "warning" < "critical". Matches the plain-string
// severity convention already used throughout internal/models and
// internal/health (no typed severity enum exists anywhere in this codebase).
var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// severityGE reports whether a ranks at or above b. An unrecognized severity
// never passes a minimum filter (fail closed).
func severityGE(a, b string) bool {
	ra, oka := severityRank[a]
	rb, okb := severityRank[b]
	if !oka || !okb {
		return false
	}
	return ra >= rb
}

// Config configures a single webhook Sink.
type Config struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Secret  string            `json:"secret,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// MinSeverity filters events at the sink. Defaults to "info".
	MinSeverity string `json:"minSeverity,omitempty"`
	// Timeout bounds each HTTP request. Defaults to 5s. JSON value is a Go
	// duration string ("5s"), matching this repo's envDuration convention
	// (cmd/netrad/main.go) rather than a bare-integer-seconds convention.
	Timeout time.Duration `json:"timeout,omitempty"`
	// MaxAttempts bounds total attempts including the first. Defaults to 3.
	MaxAttempts int `json:"maxAttempts,omitempty"`
}

func (c *Config) applyDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.MinSeverity == "" {
		c.MinSeverity = "info"
	}
}

// Sink is a single configured webhook endpoint.
type Sink struct {
	cfg    Config
	client *http.Client
}

// New validates cfg, applies defaults, and returns a Sink.
func New(cfg Config) (*Sink, error) {
	cfg.applyDefaults()
	if cfg.Name == "" {
		return nil, errors.New("webhook: Config.Name is required")
	}
	if cfg.URL == "" {
		return nil, errors.New("webhook: Config.URL is required")
	}
	return &Sink{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}}, nil
}

// Name returns the sink's configured name.
func (s *Sink) Name() string { return s.cfg.Name }

// Accepts reports whether an event at the given severity passes this sink's
// MinSeverity filter.
func (s *Sink) Accepts(severity string) bool { return severityGE(severity, s.cfg.MinSeverity) }

// Send delivers one event, one attempt, no retry (Dispatcher.deliver handles
// retries). Events below the sink's MinSeverity are silently skipped.
func (s *Sink) Send(ctx context.Context, ev Event) error {
	if !s.Accepts(ev.Severity) {
		return nil
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("webhook %s: marshal: %w", s.cfg.Name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook %s: request: %w", s.cfg.Name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netra-webhook/1")
	if s.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
		mac.Write(body)
		req.Header.Set("X-Netra-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", s.cfg.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s: status %d", s.cfg.Name, resp.StatusCode)
	}
	return nil
}
