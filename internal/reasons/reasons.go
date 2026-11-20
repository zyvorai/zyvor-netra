// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package reasons rolls FastPathEvent Action/Reason into a histogram.
// Observe-only; no payloads.
package reasons

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Bucket struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type Histogram struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Total       int       `json:"total"`
	Blocked     int       `json:"blocked"`
	Buckets     []Bucket  `json:"buckets"`
}

func Build(agents []models.AgentStatus, now time.Time) Histogram {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	type key struct{ a, r string }
	counts := map[key]int{}
	h := Histogram{GeneratedAt: now.UTC()}
	for _, ag := range agents {
		for _, ev := range ag.Events {
			k := key{a: ev.Action, r: ev.Reason}
			if k.a == "" {
				k.a = "unknown"
			}
			if k.r == "" {
				k.r = "(none)"
			}
			counts[k]++
			h.Total++
			if ev.Action == "blocked" || ev.Action == "drop" || ev.Action == "dropped" {
				h.Blocked++
			}
		}
	}
	for k, n := range counts {
		h.Buckets = append(h.Buckets, Bucket{Action: k.a, Reason: k.r, Count: n})
	}
	sort.Slice(h.Buckets, func(i, j int) bool {
		if h.Buckets[i].Count != h.Buckets[j].Count {
			return h.Buckets[i].Count > h.Buckets[j].Count
		}
		if h.Buckets[i].Action != h.Buckets[j].Action {
			return h.Buckets[i].Action < h.Buckets[j].Action
		}
		return h.Buckets[i].Reason < h.Buckets[j].Reason
	})
	return h
}
