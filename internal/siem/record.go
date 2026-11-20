// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package siem formats Netra audit events, health anomalies, and incident
// clusters for pull-based export to a SIEM or log pipeline.
//
// Formats are deliberately stdlib-only and payload-free: CEF, RFC5424
// syslog, JSONL, and a minimal OTLP/HTTP JSON Logs payload. Nothing here
// inspects application bodies, argv, or Secret contents. Export is
// observe-only — it never changes mode, leases, or rules.
package siem

import (
	"fmt"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Format names accepted by Encode and the HTTP export handlers.
const (
	FormatJSON      = "json"
	FormatJSONL     = "jsonl"
	FormatCEF       = "cef"
	FormatSyslog    = "syslog"
	FormatOTLP      = "otlp"
	FormatOTLPTrace = "otlp-trace"
)

// Record is the common envelope every formatter consumes. Fields are
// already-redacted controller observations; Details must never carry
// payloads or credentials (callers are responsible for that invariant,
// matching models.AuditEvent).
type Record struct {
	At        time.Time      `json:"at"`
	Class     string         `json:"class"` // audit, anomaly, incident
	Severity  string         `json:"severity,omitempty"`
	Actor     string         `json:"actor,omitempty"`
	Action    string         `json:"action,omitempty"`
	Target    string         `json:"target,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	Message   string         `json:"message,omitempty"`
	SourceKey string         `json:"sourceKey,omitempty"`
	Kind      string         `json:"kind,omitempty"`
	Node      string         `json:"node,omitempty"`
	Value     float64        `json:"value,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// FromAudit maps a store audit event. Details are copied as-is because
// existing mutators already refuse to persist payloads.
func FromAudit(e models.AuditEvent) Record {
	return Record{
		At:       e.At,
		Class:    "audit",
		Severity: severityForAction(e.Action),
		Actor:    e.Actor,
		Action:   e.Action,
		Target:   e.Target,
		Message:  auditMessage(e),
		Details:  e.Details,
	}
}

// FromAnomaly maps a network-health heuristic finding.
func FromAnomaly(a models.NetworkHealthAnomaly, at time.Time) Record {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return Record{
		At:        at.UTC(),
		Class:     "anomaly",
		Severity:  strings.ToLower(strings.TrimSpace(a.Severity)),
		Subject:   a.Subject,
		Message:   a.Message,
		SourceKey: a.SourceKey,
		Kind:      a.Kind,
		Value:     a.Value,
	}
}

// FromIncident maps a cross-signal incident cluster. Individual findings
// stay in Details as a count + kinds list rather than a nested dump, so
// CEF/syslog lines stay one-event-per-line.
func FromIncident(c models.IncidentCluster) Record {
	kinds := make([]string, 0, len(c.Findings))
	seen := map[string]bool{}
	for _, f := range c.Findings {
		k := strings.TrimSpace(f.Kind)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		kinds = append(kinds, k)
	}
	return Record{
		At:        c.GeneratedAt,
		Class:     "incident",
		Severity:  strings.ToLower(strings.TrimSpace(c.Severity)),
		Subject:   c.Subject,
		SourceKey: c.SourceKey,
		Message:   fmt.Sprintf("incident cluster %s (%d findings: %s)", c.SourceKey, len(c.Findings), strings.Join(kinds, ",")),
		Details: map[string]any{
			"findingCount": len(c.Findings),
			"kinds":        kinds,
		},
	}
}

// FromFlow maps one destination counter from an agent report. Class is
// "flow". Blocked>0 is warning; otherwise info. Counters and 5-tuple
// metadata only — no payloads.
func FromFlow(node string, st models.DestinationStat, at time.Time) Record {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	sev := "info"
	if st.Blocked > 0 {
		sev = "warning"
	}
	subj := st.DestinationIP
	if st.Namespace != "" && st.Pod != "" {
		subj = st.Namespace + "/" + st.Pod + " → " + st.DestinationIP
	}
	return Record{
		At:       at.UTC(),
		Class:    "flow",
		Severity: sev,
		Node:     node,
		Subject:  subj,
		Action:   st.Direction,
		Target:   st.DestinationIP,
		Kind:     st.Protocol,
		Message:  fmt.Sprintf("%s %s:%d pkts=%d bytes=%d blocked=%d", st.Protocol, st.DestinationIP, st.Port, st.Packets, st.Bytes, st.Blocked),
		Details: map[string]any{
			"sourceIp":   st.SourceIP,
			"sourcePort": st.SourcePort,
			"port":       st.Port,
			"protocol":   st.Protocol,
			"direction":  st.Direction,
			"packets":    st.Packets,
			"bytes":      st.Bytes,
			"blocked":    st.Blocked,
			"namespace":  st.Namespace,
			"pod":        st.Pod,
		},
	}
}

// IsBlocked reports whether a FastPathEvent's Action names a block/deny
// outcome (drop reason histograms and the OTEL span exporter both filter
// on this).
func IsBlocked(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "blocked", "drop", "dropped", "denied", "deny":
		return true
	default:
		return false
	}
}

// FromBlockEvent maps one blocked/dropped FastPathEvent. Class is
// "block". Always warning severity — these are enforcement outcomes,
// not passive observations. No payloads: 5-tuple, process identity
// already captured on the event, and the block reason only.
func FromBlockEvent(node string, ev models.FastPathEvent) Record {
	at := ev.ObservedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	subj := ev.DestinationIP
	if ev.Namespace != "" && ev.Pod != "" {
		subj = ev.Namespace + "/" + ev.Pod + " → " + ev.DestinationIP
	}
	return Record{
		At:       at.UTC(),
		Class:    "block",
		Severity: "warning",
		Node:     node,
		Subject:  subj,
		Action:   ev.Action,
		Target:   ev.DestinationIP,
		Kind:     firstNonEmpty(ev.Reason, "unknown"),
		Message:  fmt.Sprintf("%s %s %s:%d → %s:%d (%s)", ev.Action, ev.Protocol, ev.SourceIP, ev.SourcePort, ev.DestinationIP, ev.DestinationPort, firstNonEmpty(ev.Reason, "unknown")),
		Details: map[string]any{
			"sourceIp":        ev.SourceIP,
			"sourcePort":      ev.SourcePort,
			"destinationPort": ev.DestinationPort,
			"protocol":        ev.Protocol,
			"direction":       ev.Direction,
			"hook":            ev.Hook,
			"reason":          ev.Reason,
			"pid":             ev.PID,
			"uid":             ev.UID,
			"comm":            ev.Comm,
			"namespace":       ev.Namespace,
			"pod":             ev.Pod,
			"workloadKind":    ev.WorkloadKind,
			"workloadName":    ev.WorkloadName,
		},
	}
}

func auditMessage(e models.AuditEvent) string {
	if e.Target == "" {
		return e.Action
	}
	return e.Action + " " + e.Target
}

// severityForAction is a conservative mapping used when an audit event
// has no explicit severity. Mode/enforce/lockdown changes are warning;
// everything else is info. Never "critical" from audit alone — that
// label is reserved for health/incident heuristics.
func severityForAction(action string) string {
	a := strings.ToLower(strings.TrimSpace(action))
	switch {
	case strings.Contains(a, "enforce"), strings.Contains(a, "lockdown"), strings.Contains(a, "quarantine"), strings.Contains(a, "deny"), strings.Contains(a, "mode"):
		return "warning"
	default:
		return "info"
	}
}

// NormalizeFormat accepts the query/CLI spelling and returns a known
// constant or an error. Empty defaults to json.
func NormalizeFormat(raw string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(raw))
	if f == "" {
		return FormatJSON, nil
	}
	switch f {
	case FormatJSON, FormatJSONL, "ndjson":
		if f == "ndjson" {
			return FormatJSONL, nil
		}
		return f, nil
	case FormatCEF:
		return FormatCEF, nil
	case FormatSyslog, "rfc5424":
		return FormatSyslog, nil
	case FormatOTLP, "otlp-logs", "otel":
		return FormatOTLP, nil
	case FormatOTLPTrace, "otlptrace", "otlp-traces", "trace", "traces":
		return FormatOTLPTrace, nil
	default:
		return "", fmt.Errorf("unknown export format %q (want json, jsonl, cef, syslog, otlp, otlp-trace)", raw)
	}
}

// ContentType is the HTTP Content-Type for a normalized format.
func ContentType(format string) string {
	switch format {
	case FormatJSON, FormatOTLP, FormatOTLPTrace:
		return "application/json"
	case FormatJSONL:
		return "application/x-ndjson"
	case FormatCEF, FormatSyslog:
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
