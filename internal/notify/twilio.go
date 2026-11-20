// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TwilioKind selects SMS vs WhatsApp.
type TwilioKind int

const (
	TwilioSMS TwilioKind = iota
	TwilioWhatsApp
)

// TwilioConfig configures Twilio Messages API delivery.
type TwilioConfig struct {
	base
	Kind       TwilioKind
	AccountSID string
	AuthToken  string
	From       string
	To         []string
}

type twilioChannel struct {
	cfg     TwilioConfig
	client  *http.Client
	apiBase string // override for tests; empty → api.twilio.com
}

// NewTwilioChannel validates and returns a Twilio SMS or WhatsApp Channel.
func NewTwilioChannel(cfg TwilioConfig) (Channel, error) {
	cfg.base.applyDefaults()
	if cfg.name == "" {
		return nil, errors.New("twilio: name is required")
	}
	if strings.TrimSpace(cfg.AccountSID) == "" {
		return nil, errors.New("twilio: accountSid is required")
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return nil, errors.New("twilio: authToken is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, errors.New("twilio: from is required")
	}
	if len(cfg.To) == 0 {
		return nil, errors.New("twilio: at least one to address is required")
	}
	return &twilioChannel{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.timeout},
	}, nil
}

func (c *twilioChannel) Name() string           { return c.cfg.name }
func (c *twilioChannel) MinSeverity() string    { return c.cfg.minSeverity }
func (c *twilioChannel) Timeout() time.Duration { return c.cfg.timeout }
func (c *twilioChannel) MaxAttempts() int       { return c.cfg.maxAttempts }

func (c *twilioChannel) Send(ctx context.Context, ev Event) error {
	if !c.cfg.accepts(ev.Severity) {
		return nil
	}
	body := SMSBody(ev)
	from := c.cfg.From
	var errs []string
	for _, to := range c.cfg.To {
		toAddr := to
		fromAddr := from
		if c.cfg.Kind == TwilioWhatsApp {
			fromAddr = ensureWhatsApp(fromAddr)
			toAddr = ensureWhatsApp(toAddr)
		}
		if err := c.sendOne(ctx, fromAddr, toAddr, body); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("twilio %s: %s", c.cfg.name, strings.Join(errs, "; "))
	}
	return nil
}

func ensureWhatsApp(addr string) string {
	if strings.HasPrefix(strings.ToLower(addr), "whatsapp:") {
		return addr
	}
	return "whatsapp:" + addr
}

func (c *twilioChannel) sendOne(ctx context.Context, from, to, body string) error {
	base := c.apiBase
	if base == "" {
		base = "https://api.twilio.com"
	}
	endpoint := fmt.Sprintf(
		"%s/2010-04-01/Accounts/%s/Messages.json",
		strings.TrimRight(base, "/"),
		url.PathEscape(c.cfg.AccountSID),
	)
	form := url.Values{}
	form.Set("From", from)
	form.Set("To", to)
	form.Set("Body", body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.SetBasicAuth(c.cfg.AccountSID, c.cfg.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "netra-notify/1")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(slurp)))
	}
	return nil
}
