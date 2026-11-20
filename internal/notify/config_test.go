// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package notify

import (
	"strings"
	"testing"
)

func TestParseChannelsAllTypes(t *testing.T) {
	raw := `[
	  {"type":"webhook","name":"wh","url":"https://example/hook","minSeverity":"warning","timeout":"3s"},
	  {"type":"email","name":"mail","smtpHost":"smtp.example:587","from":"a@b","to":["c@d"]},
	  {"type":"slack","name":"sl","mode":"incoming","url":"https://hooks.slack.com/x"},
	  {"type":"slack","name":"slapi","mode":"api","token":"xoxb-t","channel":"#ops"},
	  {"type":"teams","name":"tm","url":"https://outlook.office.com/webhook/x"},
	  {"type":"twilio_sms","name":"sms","accountSid":"ACxxx","authToken":"tok","from":"+1","to":["+2"]},
	  {"type":"twilio_whatsapp","name":"wa","accountSid":"ACxxx","authToken":"tok","from":"whatsapp:+1","to":["whatsapp:+2"]},
	  {"type":"httpbridge","name":"br","url":"https://bridge/notify","channelHint":"sms","secret":"s"}
	]`
	chs, err := ParseChannels(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(chs) != 8 {
		t.Fatalf("got %d channels", len(chs))
	}
}

func TestParseChannelsUnknownType(t *testing.T) {
	_, err := ParseChannels(`[{"type":"carrier_pigeon","name":"x"}]`)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("expected unknown type error, got %v", err)
	}
}

func TestParseChannelsMissingName(t *testing.T) {
	_, err := ParseChannels(`[{"type":"webhook","url":"https://example"}]`)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseLegacyWebhooks(t *testing.T) {
	chs, err := ParseLegacyWebhooks(`[{"name":"slack","url":"https://example/hook","minSeverity":"critical"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(chs) != 1 || chs[0].Name() != "slack" || chs[0].MinSeverity() != "critical" {
		t.Fatalf("unexpected: name=%s min=%s", chs[0].Name(), chs[0].MinSeverity())
	}
}

func TestFormatHelpers(t *testing.T) {
	ev := Event{Source: "health", Kind: "tcp-rto", Severity: "warning", Subject: "pod/a", Message: "elevated RTO"}
	title := Title(ev)
	if !strings.Contains(title, "WARNING") || !strings.Contains(title, "tcp-rto") {
		t.Fatalf("title=%q", title)
	}
	plain := Plain(ev)
	if !strings.Contains(plain, "elevated RTO") || !strings.Contains(plain, "source=health") {
		t.Fatalf("plain=%q", plain)
	}
	long := Event{Message: strings.Repeat("x", 2000)}
	if len(SMSBody(long)) > 1500 {
		t.Fatalf("SMS body not capped: %d", len(SMSBody(long)))
	}
}
