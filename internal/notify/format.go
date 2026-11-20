// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Title builds a short one-line subject suitable for email/SMS headers.
func Title(ev Event) string {
	sev := strings.ToUpper(ev.Severity)
	if sev == "" {
		sev = "INFO"
	}
	kind := ev.Kind
	if kind == "" {
		kind = "alert"
	}
	subj := ev.Subject
	if subj == "" {
		subj = ev.Source
	}
	return fmt.Sprintf("[Netra][%s] %s · %s", sev, kind, subj)
}

// Plain builds a multi-line human-readable body for email, SMS, WhatsApp.
func Plain(ev Event) string {
	var b strings.Builder
	b.WriteString(Title(ev))
	b.WriteByte('\n')
	if ev.Message != "" {
		b.WriteString(ev.Message)
		b.WriteByte('\n')
	}
	if ev.Card != "" && ev.Card != ev.Message {
		b.WriteString(ev.Card)
		b.WriteByte('\n')
	} else if ev.Text != "" && ev.Text != ev.Message && ev.Text != ev.Card {
		b.WriteString(ev.Text)
		b.WriteByte('\n')
	}
	if ev.Source != "" {
		fmt.Fprintf(&b, "source=%s", ev.Source)
		if ev.Node != "" {
			fmt.Fprintf(&b, " node=%s", ev.Node)
		}
		if ev.Fingerprint != "" {
			fmt.Fprintf(&b, " fingerprint=%s", ev.Fingerprint)
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// SMSBody is a short plain body capped for SMS (Twilio soft limit ~1600).
func SMSBody(ev Event) string {
	s := Plain(ev)
	const max = 1500
	if len(s) <= max {
		return s
	}
	cut := max - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
