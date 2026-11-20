// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"context"

	"github.com/zyvorai/netra/internal/webhook"
)

// webhookChannel adapts webhook.Sink to the Channel interface.
type webhookChannel struct {
	base
	sink *webhook.Sink
}

// NewWebhookChannel wraps a webhook.Config as a Channel.
func NewWebhookChannel(cfg webhook.Config) (Channel, error) {
	sink, err := webhook.New(cfg)
	if err != nil {
		return nil, err
	}
	b := base{
		name:        cfg.Name,
		minSeverity: cfg.MinSeverity,
		timeout:     cfg.Timeout,
		maxAttempts: cfg.MaxAttempts,
	}
	b.applyDefaults()
	return &webhookChannel{base: b, sink: sink}, nil
}

func (c *webhookChannel) Send(ctx context.Context, ev Event) error {
	return c.sink.Send(ctx, toWebhookEvent(ev))
}

func toWebhookEvent(ev Event) webhook.Event {
	return webhook.Event{
		Source:      ev.Source,
		Kind:        ev.Kind,
		Severity:    ev.Severity,
		Subject:     ev.Subject,
		Message:     ev.Message,
		Value:       ev.Value,
		Node:        ev.Node,
		Timestamp:   ev.Timestamp,
		Fingerprint: ev.Fingerprint,
		Card:        ev.Card,
		Text:        ev.Text,
	}
}
