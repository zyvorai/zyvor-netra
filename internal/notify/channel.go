// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"context"
	"time"
)

// Channel is a single outbound notification destination.
type Channel interface {
	Name() string
	// MinSeverity is the sink filter (info/warning/critical). Send should
	// still no-op for events below this threshold.
	MinSeverity() string
	// Timeout bounds a single Send attempt.
	Timeout() time.Duration
	// MaxAttempts bounds total attempts including the first (dispatcher retries).
	MaxAttempts() int
	Send(ctx context.Context, ev Event) error
}

// base holds shared fields every concrete channel config carries.
type base struct {
	name        string
	minSeverity string
	timeout     time.Duration
	maxAttempts int
}

func (b *base) applyDefaults() {
	if b.timeout <= 0 {
		b.timeout = 5 * time.Second
	}
	if b.maxAttempts <= 0 {
		b.maxAttempts = 3
	}
	if b.minSeverity == "" {
		b.minSeverity = "info"
	}
}

func (b base) Name() string           { return b.name }
func (b base) MinSeverity() string    { return b.minSeverity }
func (b base) Timeout() time.Duration { return b.timeout }
func (b base) MaxAttempts() int       { return b.maxAttempts }

func (b base) accepts(severity string) bool {
	return SeverityGE(severity, b.minSeverity)
}
