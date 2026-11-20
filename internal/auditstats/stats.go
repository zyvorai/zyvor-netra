// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package auditstats rolls the in-memory audit log into actor/action
// counts and hourly buckets. Observe-only; it never writes the store.
package auditstats

import (
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type HourBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

type Summary struct {
	Total    int          `json:"total"`
	ByActor  []Count      `json:"byActor"`
	ByAction []Count      `json:"byAction"`
	ByHour   []HourBucket `json:"byHour"`
	Since    time.Time    `json:"since,omitempty"`
	Until    time.Time    `json:"until,omitempty"`
}

// Summarize aggregates events. A zero since/until includes everything.
func Summarize(events []models.AuditEvent, since, until time.Time) Summary {
	actors := map[string]int{}
	actions := map[string]int{}
	hours := map[string]int{}
	var minT, maxT time.Time
	total := 0
	for _, e := range events {
		at := e.At.UTC()
		if !since.IsZero() && at.Before(since.UTC()) {
			continue
		}
		if !until.IsZero() && !at.Before(until.UTC()) {
			continue
		}
		total++
		actor := strings.TrimSpace(e.Actor)
		if actor == "" {
			actor = "unknown"
		}
		action := strings.TrimSpace(e.Action)
		if action == "" {
			action = "unknown"
		}
		actors[actor]++
		actions[action]++
		hours[at.Truncate(time.Hour).Format(time.RFC3339)]++
		if minT.IsZero() || at.Before(minT) {
			minT = at
		}
		if maxT.IsZero() || at.After(maxT) {
			maxT = at
		}
	}
	return Summary{
		Total:    total,
		ByActor:  topCounts(actors, 20),
		ByAction: topCounts(actions, 20),
		ByHour:   hourBuckets(hours),
		Since:    minT,
		Until:    maxT,
	}
}

func topCounts(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func hourBuckets(m map[string]int) []HourBucket {
	out := make([]HourBucket, 0, len(m))
	for k, v := range m {
		out = append(out, HourBucket{Hour: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hour < out[j].Hour })
	return out
}
