// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/webhook"
)

// channelJSON is the discriminated config object for NETRA_ALERT_CHANNELS.
type channelJSON struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	MinSeverity string            `json:"minSeverity,omitempty"`
	Timeout     string            `json:"timeout,omitempty"`
	MaxAttempts int               `json:"maxAttempts,omitempty"`
	URL         string            `json:"url,omitempty"`
	Secret      string            `json:"secret,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`

	// email
	SMTPHost string   `json:"smtpHost,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`

	// slack
	Mode    string `json:"mode,omitempty"`
	Token   string `json:"token,omitempty"`
	Channel string `json:"channel,omitempty"`

	// twilio
	AccountSID string `json:"accountSid,omitempty"`
	AuthToken  string `json:"authToken,omitempty"`

	// httpbridge
	ChannelHint string `json:"channelHint,omitempty"`
}

// ParseChannels decodes NETRA_ALERT_CHANNELS JSON into concrete Channel
// implementations. Unknown types return an error.
func ParseChannels(raw string) ([]Channel, error) {
	var in []channelJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("notify: parse NETRA_ALERT_CHANNELS: %w", err)
	}
	out := make([]Channel, 0, len(in))
	for i, c := range in {
		ch, err := buildChannel(c)
		if err != nil {
			name := c.Name
			if name == "" {
				name = fmt.Sprintf("#%d", i)
			}
			return nil, fmt.Errorf("notify: channel %q: %w", name, err)
		}
		out = append(out, ch)
	}
	return out, nil
}

// ParseLegacyWebhooks converts NETRA_ALERT_WEBHOOKS JSON into webhook channels.
func ParseLegacyWebhooks(raw string) ([]Channel, error) {
	cfgs, err := webhook.ParseConfigs(raw)
	if err != nil {
		return nil, err
	}
	out := make([]Channel, 0, len(cfgs))
	for _, sc := range cfgs {
		ch, err := NewWebhookChannel(sc)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, nil
}

func buildChannel(c channelJSON) (Channel, error) {
	typ := strings.ToLower(strings.TrimSpace(c.Type))
	if typ == "" {
		return nil, fmt.Errorf("type is required")
	}
	if strings.TrimSpace(c.Name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	timeout, err := parseTimeout(c.Timeout)
	if err != nil {
		return nil, err
	}
	b := base{
		name:        c.Name,
		minSeverity: c.MinSeverity,
		timeout:     timeout,
		maxAttempts: c.MaxAttempts,
	}
	b.applyDefaults()

	switch typ {
	case "webhook":
		return NewWebhookChannel(webhook.Config{
			Name:        c.Name,
			URL:         c.URL,
			Secret:      c.Secret,
			Headers:     c.Headers,
			MinSeverity: b.minSeverity,
			Timeout:     b.timeout,
			MaxAttempts: b.maxAttempts,
		})
	case "email":
		return NewEmailChannel(EmailConfig{
			base:     b,
			SMTPHost: c.SMTPHost,
			From:     c.From,
			To:       c.To,
			Username: c.Username,
			Password: c.Password,
		})
	case "slack":
		return NewSlackChannel(SlackConfig{
			base:    b,
			Mode:    c.Mode,
			URL:     c.URL,
			Token:   c.Token,
			Channel: c.Channel,
		})
	case "teams":
		return NewTeamsChannel(TeamsConfig{
			base: b,
			URL:  c.URL,
		})
	case "twilio_sms":
		return NewTwilioChannel(TwilioConfig{
			base:       b,
			Kind:       TwilioSMS,
			AccountSID: c.AccountSID,
			AuthToken:  c.AuthToken,
			From:       c.From,
			To:         c.To,
		})
	case "twilio_whatsapp":
		return NewTwilioChannel(TwilioConfig{
			base:       b,
			Kind:       TwilioWhatsApp,
			AccountSID: c.AccountSID,
			AuthToken:  c.AuthToken,
			From:       c.From,
			To:         c.To,
		})
	case "httpbridge":
		return NewHTTPBridgeChannel(HTTPBridgeConfig{
			base:        b,
			URL:         c.URL,
			Secret:      c.Secret,
			Headers:     c.Headers,
			ChannelHint: c.ChannelHint,
		})
	default:
		return nil, fmt.Errorf("unknown type %q", c.Type)
	}
}

func parseTimeout(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q: %w", s, err)
	}
	return d, nil
}
