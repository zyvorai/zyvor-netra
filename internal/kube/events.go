// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kube

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
)

// WorkloadEvent is one Kubernetes Warning attached to a Pod. Message is
// truncated. Messages that look like credentials are omitted.
type WorkloadEvent struct {
	Namespace      string    `json:"namespace,omitempty"`
	Pod            string    `json:"pod"`
	Reason         string    `json:"reason,omitempty"`
	Message        string    `json:"message,omitempty"`
	MessageOmitted bool      `json:"messageOmitted,omitempty"`
	Count          int       `json:"count,omitempty"`
	LastSeen       time.Time `json:"lastSeen,omitempty"`
}

// WarningEvents is GET /api/v1/insights/workload-events.
type WarningEvents struct {
	Available   bool            `json:"available"`
	Events      []WorkloadEvent `json:"events"`
	Error       string          `json:"error,omitempty"`
	Limitations []string        `json:"limitations"`
}

// EventLimitations states what this join is not.
func EventLimitations() []string {
	return []string{
		"Kubernetes Warning events for Pods only (OOMKilled, Unhealthy, BackOff, Failed, and the rest of type=Warning).",
		"Journal, dmesg, and node dumps are not collected.",
		"Messages containing password, secret, token, bearer, or authorization are omitted.",
	}
}

const maxWarningEvents = 200

var errListDone = errors.New("list done")

// ListWarningEvents lists pod Warning events. ns empty means all namespaces.
func (c *Client) ListWarningEvents(ctx context.Context, ns string) ([]WorkloadEvent, error) {
	p := "/api/v1/events?fieldSelector=" + url.QueryEscape("type=Warning,involvedObject.kind=Pod")
	if strings.TrimSpace(ns) != "" {
		p = "/api/v1/namespaces/" + esc(ns) + "/events?fieldSelector=" + url.QueryEscape("type=Warning,involvedObject.kind=Pod")
	}
	var out []WorkloadEvent
	err := c.listPages(ctx, p, func(b []byte) error {
		out = append(out, ParseWarningEvents(b)...)
		if len(out) >= maxWarningEvents {
			return errListDone
		}
		return nil
	})
	if err != nil && !errors.Is(err, errListDone) {
		return nil, err
	}
	if len(out) > maxWarningEvents {
		out = out[:maxWarningEvents]
	}
	return out, nil
}

// ParseWarningEvents decodes a core v1 EventList and keeps pod warnings.
func ParseWarningEvents(b []byte) []WorkloadEvent {
	var list struct {
		Items []struct {
			Type           string `json:"type"`
			Reason         string `json:"reason"`
			Message        string `json:"message"`
			Count          int    `json:"count"`
			InvolvedObject struct {
				Kind, Name, Namespace string
			} `json:"involvedObject"`
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			LastTimestamp time.Time `json:"lastTimestamp"`
			EventTime     time.Time `json:"eventTime"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil
	}
	out := make([]WorkloadEvent, 0, len(list.Items))
	for _, it := range list.Items {
		if it.Type != "" && it.Type != "Warning" {
			continue
		}
		if it.InvolvedObject.Kind != "Pod" || it.InvolvedObject.Name == "" {
			continue
		}
		ev := WorkloadEvent{
			Namespace: it.InvolvedObject.Namespace,
			Pod:       it.InvolvedObject.Name,
			Reason:    it.Reason,
			Count:     it.Count,
			LastSeen:  it.LastTimestamp,
		}
		if ev.Namespace == "" {
			ev.Namespace = it.Metadata.Namespace
		}
		if ev.LastSeen.IsZero() {
			ev.LastSeen = it.EventTime
		}
		msg, omit := scrubEventMessage(it.Message)
		ev.Message = msg
		ev.MessageOmitted = omit
		out = append(out, ev)
		if len(out) >= maxWarningEvents {
			break
		}
	}
	return out
}

func scrubEventMessage(msg string) (string, bool) {
	lower := strings.ToLower(msg)
	for _, w := range []string{"password", "secret", "token", "bearer", "authorization"} {
		if strings.Contains(lower, w) {
			return "", true
		}
	}
	msg = strings.TrimSpace(msg)
	if len(msg) > 180 {
		msg = msg[:180]
	}
	return msg, false
}
