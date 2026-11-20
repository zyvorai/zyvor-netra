// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package notify delivers alert events to one or more notification channels
// (webhook, email, Slack, Teams, Twilio SMS/WhatsApp, HTTP bridge). A
// Dispatcher fans events out concurrently; delivery is
// at-least-once-best-effort, not exactly-once, and a full queue drops
// events rather than blocking the publisher.
package notify

import "time"

// Event is the payload delivered to channels. Its fields mirror
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

// SeverityGE reports whether a ranks at or above b. An unrecognized severity
// never passes a minimum filter (fail closed).
func SeverityGE(a, b string) bool {
	ra, oka := severityRank[a]
	rb, okb := severityRank[b]
	if !oka || !okb {
		return false
	}
	return ra >= rb
}
