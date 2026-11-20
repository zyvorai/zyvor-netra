// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package siem

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestNormalizeFormat(t *testing.T) {
	cases := map[string]string{
		"":        FormatJSON,
		"JSON":    FormatJSON,
		"ndjson":  FormatJSONL,
		"jsonl":   FormatJSONL,
		"cef":     FormatCEF,
		"rfc5424": FormatSyslog,
		"otel":    FormatOTLP,
	}
	for in, want := range cases {
		got, err := NormalizeFormat(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
	if _, err := NormalizeFormat("pcap"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestFromAuditAndCEFRoundTripShape(t *testing.T) {
	at := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rec := FromAudit(models.AuditEvent{
		At:     at,
		Actor:  "netractl",
		Action: "ebpf.mode",
		Target: "enforce",
		Details: map[string]any{
			"lease": "5m",
		},
	})
	if rec.Class != "audit" || rec.Severity != "warning" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	line := FormatCEFLine(rec)
	if !strings.HasPrefix(line, "CEF:0|Zyvor|Netra|1.0|ebpf.mode|") {
		t.Fatalf("cef prefix: %s", line)
	}
	if strings.Contains(line, "\n") {
		t.Fatal("CEF line must be single-line")
	}
	if !strings.Contains(line, "suser=netractl") {
		t.Fatalf("missing actor: %s", line)
	}
	if !strings.Contains(line, "cs2=enforce") {
		t.Fatalf("missing target: %s", line)
	}
}

func TestCEFEscapesPipesAndNewlines(t *testing.T) {
	line := FormatCEFLine(Record{
		At:      time.Unix(0, 0).UTC(),
		Class:   "audit",
		Action:  "deny|add",
		Message: "blocked 1.2.3.4\nnext",
	})
	if !strings.Contains(line, `deny\|add`) {
		t.Fatalf("pipe not escaped: %s", line)
	}
	if !strings.Contains(line, `\n`) {
		t.Fatalf("newline not escaped: %s", line)
	}
	if strings.Contains(line, "\n") {
		t.Fatal("raw newline leaked into CEF line")
	}
}

func TestSyslogRFC5424(t *testing.T) {
	at := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	line := FormatSyslogLine(Record{
		At:        at,
		Class:     "anomaly",
		Severity:  "critical",
		Node:      "node-a",
		Kind:      "high_rtt",
		SourceKey: `workload:"api"]`,
		Message:   `dns "fail" ] more`,
	})
	if !strings.HasPrefix(line, "<106>1 ") { // facility 13, sev 2 → 13*8+2=106
		t.Fatalf("PRI: %s", line)
	}
	if !strings.Contains(line, " node-a netra - - [netra@zyvor ") {
		t.Fatalf("header: %s", line)
	}
	if !strings.Contains(line, `class="anomaly"`) {
		t.Fatalf("sd: %s", line)
	}
	if !strings.Contains(line, `sourceKey="workload:\"api\"\]"`) {
		t.Fatalf("SD quotes/brackets must be escaped: %s", line)
	}
}

func TestEncodeJSONLAndOTLP(t *testing.T) {
	recs := []Record{
		FromAnomaly(models.NetworkHealthAnomaly{
			Severity:  "warning",
			Kind:      "retransmit_pressure",
			Subject:   "workload:default:deploy:api",
			Message:   "retransmit ratio elevated",
			Value:     0.12,
			SourceKey: "workload:default:deploy:api",
		}, time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)),
		FromIncident(models.IncidentCluster{
			GeneratedAt: time.Date(2026, 9, 14, 12, 1, 0, 0, time.UTC),
			SourceKey:   "workload:default:deploy:api",
			Subject:     "api",
			Severity:    "high",
			Findings: []models.IncidentFinding{
				{Kind: "health", Severity: "warning"},
				{Kind: "drift", Severity: "warning"},
			},
		}),
	}
	raw, err := Encode(FormatJSONL, recs)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 jsonl lines, got %d %q", len(lines), string(raw))
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
	}

	otlp, err := Encode(FormatOTLP, recs)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(otlp, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["resourceLogs"]; !ok {
		t.Fatalf("otlp missing resourceLogs: %s", otlp)
	}
}

func TestEncodeRejectsUnknown(t *testing.T) {
	if _, err := Encode("pcap", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestEmptyEncodeStillValid(t *testing.T) {
	for _, f := range []string{FormatJSON, FormatJSONL, FormatCEF, FormatSyslog, FormatOTLP} {
		b, err := Encode(f, nil)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if f == FormatJSON || f == FormatOTLP {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("%s not json: %v", f, err)
			}
		}
	}
}

func TestFromFlowBlockedIsWarning(t *testing.T) {
	rec := FromFlow("n1", models.DestinationStat{
		DestinationIP: "203.0.113.9",
		Port:          443,
		Protocol:      "TCP",
		Packets:       10,
		Blocked:       3,
		Namespace:     "prod",
		Pod:           "api-1",
	}, time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC))
	if rec.Class != "flow" || rec.Severity != "warning" {
		t.Fatalf("%#v", rec)
	}
	if rec.Subject != "prod/api-1 → 203.0.113.9" {
		t.Fatalf("subject=%s", rec.Subject)
	}
}

func TestForwarderUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		got <- string(buf[:n])
	}()
	fwd, err := NewForwarder(ForwardConfig{Network: "udp", Addr: pc.LocalAddr().String(), Format: FormatSyslog}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := fwd.Send([]Record{FromAudit(models.AuditEvent{At: time.Now().UTC(), Actor: "t", Action: "ebpf.mode", Target: "observe"})}); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-got:
		if !strings.Contains(body, "netra") {
			t.Fatalf("payload: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no udp payload")
	}
}

func TestIsBlocked(t *testing.T) {
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{"blocked", true}, {"drop", true}, {"dropped", true}, {"denied", true}, {"deny", true},
		{"BLOCKED", true}, {" dropped ", true},
		{"allowed", false}, {"", false}, {"observed", false},
	} {
		if got := IsBlocked(tc.action); got != tc.want {
			t.Fatalf("IsBlocked(%q) = %v, want %v", tc.action, got, tc.want)
		}
	}
}

func TestFromBlockEventShape(t *testing.T) {
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	rec := FromBlockEvent("n1", models.FastPathEvent{
		Action:          "blocked",
		Reason:          "deny-cidr",
		SourceIP:        "10.0.0.5",
		SourcePort:      54321,
		DestinationIP:   "203.0.113.20",
		DestinationPort: 443,
		Protocol:        "TCP",
		Namespace:       "prod",
		Pod:             "api-1",
		ObservedAt:      at,
	})
	if rec.Class != "block" || rec.Severity != "warning" {
		t.Fatalf("%#v", rec)
	}
	if rec.Subject != "prod/api-1 → 203.0.113.20" {
		t.Fatalf("subject=%s", rec.Subject)
	}
	if rec.Kind != "deny-cidr" {
		t.Fatalf("kind=%s", rec.Kind)
	}
	if !rec.At.Equal(at) {
		t.Fatalf("at=%v want %v", rec.At, at)
	}
}

func TestEncodeOTLPTraceRoundTrip(t *testing.T) {
	body, err := Encode(FormatOTLPTrace, []Record{
		FromBlockEvent("n1", models.FastPathEvent{Action: "blocked", Reason: "syn-drop", DestinationIP: "203.0.113.20"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, body)
	}
	if _, ok := doc["resourceSpans"]; !ok {
		t.Fatalf("missing resourceSpans: %s", body)
	}
	if strings.Contains(string(body), `"resourceLogs"`) {
		t.Fatalf("otlp-trace must not use the logs shape: %s", body)
	}
}
