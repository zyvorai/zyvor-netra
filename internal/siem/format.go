// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package siem

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	cefVendor  = "Zyvor"
	cefProduct = "Netra"
	cefVersion = "1.0"
	syslogApp  = "netra"
)

// Encode renders records in the requested format. JSON is a single
// object {"format","count","items"}; JSONL/CEF/syslog are one record
// per line; OTLP is one LogsData document.
func Encode(format string, records []Record) ([]byte, error) {
	f, err := NormalizeFormat(format)
	if err != nil {
		return nil, err
	}
	switch f {
	case FormatJSON:
		return json.MarshalIndent(map[string]any{
			"format": FormatJSON,
			"count":  len(records),
			"items":  records,
		}, "", "  ")
	case FormatJSONL:
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		for _, r := range records {
			if err := enc.Encode(r); err != nil {
				return nil, err
			}
		}
		return b.Bytes(), nil
	case FormatCEF:
		var b bytes.Buffer
		for i, r := range records {
			if i > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(FormatCEFLine(r))
		}
		if len(records) > 0 {
			b.WriteByte('\n')
		}
		return b.Bytes(), nil
	case FormatSyslog:
		var b bytes.Buffer
		for _, r := range records {
			b.WriteString(FormatSyslogLine(r))
			b.WriteByte('\n')
		}
		return b.Bytes(), nil
	case FormatOTLP:
		return json.MarshalIndent(otlpLogs(records), "", "  ")
	case FormatOTLPTrace:
		return json.MarshalIndent(otlpTraces(records), "", "  ")
	default:
		return nil, fmt.Errorf("unhandled format %q", f)
	}
}

// FormatCEFLine is one ArcSight CEF 0 record. Extension values are
// escaped per the CEF spec (\ = \\, | = \|, newline = \n).
func FormatCEFLine(r Record) string {
	sev := cefSeverity(r.Severity)
	sig := firstNonEmpty(r.Action, r.Kind, r.Class, "event")
	name := firstNonEmpty(r.Message, r.Subject, r.Target, sig)
	ext := []string{
		"cs1Label=class",
		"cs1=" + cefEscape(r.Class),
		"start=" + formatMillis(r.At),
	}
	if r.Actor != "" {
		ext = append(ext, "suser="+cefEscape(r.Actor))
	}
	if r.Target != "" {
		ext = append(ext, "cs2Label=target", "cs2="+cefEscape(r.Target))
	}
	if r.Subject != "" {
		ext = append(ext, "cs3Label=subject", "cs3="+cefEscape(r.Subject))
	}
	if r.SourceKey != "" {
		ext = append(ext, "cs4Label=sourceKey", "cs4="+cefEscape(r.SourceKey))
	}
	if r.Kind != "" {
		ext = append(ext, "cs5Label=kind", "cs5="+cefEscape(r.Kind))
	}
	if r.Node != "" {
		ext = append(ext, "dhost="+cefEscape(r.Node))
	}
	if r.Value != 0 {
		ext = append(ext, "cn1Label=value", "cn1="+strconv.FormatFloat(r.Value, 'f', -1, 64))
	}
	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		cefVendor, cefProduct, cefVersion,
		cefEscape(sig), cefEscape(name), sev, strings.Join(ext, " "))
}

// FormatSyslogLine is one RFC5424 line with structured-data in the
// netra@zyvor SD-ID. PRI uses facility 13 (log audit) + severity.
func FormatSyslogLine(r Record) string {
	pri := 13*8 + syslogSeverity(r.Severity)
	ts := r.At.UTC().Format(time.RFC3339Nano)
	if r.At.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	host := firstNonEmpty(r.Node, "-")
	sd := []string{
		"class=\"" + sdEscape(r.Class) + "\"",
		"severity=\"" + sdEscape(r.Severity) + "\"",
	}
	if r.Actor != "" {
		sd = append(sd, "actor=\""+sdEscape(r.Actor)+"\"")
	}
	if r.Action != "" {
		sd = append(sd, "action=\""+sdEscape(r.Action)+"\"")
	}
	if r.Target != "" {
		sd = append(sd, "target=\""+sdEscape(r.Target)+"\"")
	}
	if r.SourceKey != "" {
		sd = append(sd, "sourceKey=\""+sdEscape(r.SourceKey)+"\"")
	}
	msg := firstNonEmpty(r.Message, r.Subject, r.Action, r.Class)
	return fmt.Sprintf("<%d>1 %s %s %s - - [%s %s] %s",
		pri, ts, host, syslogApp, "netra@zyvor", strings.Join(sd, " "), syslogMsg(msg))
}

func cefSeverity(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high":
		return 8
	case "warning", "medium":
		return 5
	case "low":
		return 3
	default:
		return 1
	}
}

func syslogSeverity(s string) int {
	// RFC5424: 0 emerg … 7 debug. Map Netra's 3-level strings onto that.
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 2 // critical
	case "high":
		return 3 // error
	case "warning", "medium":
		return 4 // warning
	default:
		return 6 // informational
	}
}

func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func sdEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "]", `\]`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func syslogMsg(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func formatMillis(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UTC().UnixMilli(), 10)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// otlpLogs is the smallest OTLP/HTTP JSON Logs body a collector will
// accept. Resource attributes identify Netra; each record is one log
// record. No traces/spans — the backlog item "OTEL spans for block/deny"
// can grow a traces exporter later without changing this logs shape.
func otlpLogs(records []Record) map[string]any {
	logs := make([]map[string]any, 0, len(records))
	for _, r := range records {
		body, _ := json.Marshal(r)
		attrs := []map[string]any{
			otlpStr("netra.class", r.Class),
		}
		if r.Severity != "" {
			attrs = append(attrs, otlpStr("netra.severity", r.Severity))
		}
		if r.Action != "" {
			attrs = append(attrs, otlpStr("netra.action", r.Action))
		}
		if r.Actor != "" {
			attrs = append(attrs, otlpStr("netra.actor", r.Actor))
		}
		if r.Target != "" {
			attrs = append(attrs, otlpStr("netra.target", r.Target))
		}
		if r.Kind != "" {
			attrs = append(attrs, otlpStr("netra.kind", r.Kind))
		}
		if r.SourceKey != "" {
			attrs = append(attrs, otlpStr("netra.source_key", r.SourceKey))
		}
		logs = append(logs, map[string]any{
			"timeUnixNano":         formatNano(r.At),
			"severityText":         firstNonEmpty(r.Severity, "INFO"),
			"severityNumber":       otlpSeverityNumber(r.Severity),
			"body":                 map[string]any{"stringValue": string(body)},
			"attributes":           attrs,
			"observedTimeUnixNano": formatNano(time.Now().UTC()),
		})
	}
	return map[string]any{
		"resourceLogs": []map[string]any{{
			"resource": map[string]any{
				"attributes": []map[string]any{
					otlpStr("service.name", "netra"),
					otlpStr("service.namespace", "zyvor"),
					otlpStr("telemetry.sdk.language", "go"),
					otlpStr("telemetry.sdk.name", "netra-siem"),
				},
			},
			"scopeLogs": []map[string]any{{
				"scope":      map[string]any{"name": "github.com/zyvorai/netra/internal/siem", "version": cefVersion},
				"logRecords": logs,
			}},
		}},
	}
}

// otlpTraces renders each record as one zero-parent, zero-child OTLP
// span — not a real distributed trace, but the smallest shape a
// trace-based backend (Tempo, Jaeger via OTLP) will accept and display
// on its own timeline. Each record gets a fresh random trace/span ID;
// there is no causal linkage between records, matching the backlog
// item's own framing ("export of existing ringbuf events as traces").
// This encoder is shared across every export endpoint, not just
// /export/blocks, so span status is derived from Severity rather than
// hardcoded — a block/deny record (always "warning") reads as ERROR,
// but a plain info-level audit/flow record exported this way doesn't
// falsely look like a failure.
func otlpTraces(records []Record) map[string]any {
	spans := make([]map[string]any, 0, len(records))
	for _, r := range records {
		start := r.At
		if start.IsZero() {
			start = time.Now().UTC()
		}
		attrs := []map[string]any{
			otlpStr("netra.class", r.Class),
		}
		if r.Node != "" {
			attrs = append(attrs, otlpStr("netra.node", r.Node))
		}
		if r.Kind != "" {
			attrs = append(attrs, otlpStr("netra.reason", r.Kind))
		}
		if r.Subject != "" {
			attrs = append(attrs, otlpStr("netra.subject", r.Subject))
		}
		if r.Target != "" {
			attrs = append(attrs, otlpStr("netra.target", r.Target))
		}
		spans = append(spans, map[string]any{
			"traceId":           randomHexID(16),
			"spanId":            randomHexID(8),
			"name":              firstNonEmpty(r.Action, "netra.block"),
			"kind":              1, // SPAN_KIND_INTERNAL
			"startTimeUnixNano": formatNano(start),
			"endTimeUnixNano":   formatNano(start.Add(time.Microsecond)),
			"attributes":        attrs,
			"status":            map[string]any{"code": otlpSpanStatusCode(r.Severity), "message": firstNonEmpty(r.Message, r.Action)},
		})
	}
	return map[string]any{
		"resourceSpans": []map[string]any{{
			"resource": map[string]any{
				"attributes": []map[string]any{
					otlpStr("service.name", "netra"),
					otlpStr("service.namespace", "zyvor"),
					otlpStr("telemetry.sdk.language", "go"),
					otlpStr("telemetry.sdk.name", "netra-siem"),
				},
			},
			"scopeSpans": []map[string]any{{
				"scope": map[string]any{"name": "github.com/zyvorai/netra/internal/siem", "version": cefVersion},
				"spans": spans,
			}},
		}},
	}
}

// randomHexID returns n random bytes as a lowercase hex string (falls
// back to an all-zero ID, per the OTLP spec's own invalid-but-parseable
// convention, on the practically-impossible crypto/rand failure case).
func randomHexID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString(make([]byte, n))
	}
	return hex.EncodeToString(b)
}

func otlpStr(key, value string) map[string]any {
	return map[string]any{
		"key":   key,
		"value": map[string]any{"stringValue": value},
	}
}

func formatNano(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return strconv.FormatInt(t.UTC().UnixNano(), 10)
}

// otlpSpanStatusCode maps Netra's 3-level severity onto the OTLP Span
// Status codes: https://opentelemetry.io/docs/specs/otel/trace/api/#set-status
// UNSET(0) for info-level records, ERROR(2) for anything Netra already
// treats as elevated. OTLP has no separate "warning" span status.
func otlpSpanStatusCode(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "warning", "medium":
		return 2 // STATUS_CODE_ERROR
	default:
		return 0 // STATUS_CODE_UNSET
	}
}

func otlpSeverityNumber(s string) int {
	// https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 21
	case "high":
		return 17
	case "warning", "medium":
		return 13
	case "low":
		return 9
	default:
		return 9
	}
}
