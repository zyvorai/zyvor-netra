// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Package scorecard collapses health, coverage, fleet, and drop reasons
// into one 0-100 board. Observe-only arithmetic.
package scorecard

import (
	"time"

	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/reasons"
	"github.com/zyvorai/netra/internal/report"
)

type Card struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Score       int       `json:"score"`
	Band        string    `json:"band"`
	Headline    string    `json:"headline"`
	Health      int       `json:"healthScore"`
	StaleAgents int       `json:"staleAgents"`
	Detached    int       `json:"detachedPrograms"`
	MissingMaps int       `json:"missingMaps"`
	BlockedEv   int       `json:"blockedEvents"`
	Notes       []string  `json:"notes"`
}

func Build(snap report.Snapshot, cov coverage.Matrix, fl fleet.Inventory, rs reasons.Histogram, now time.Time) Card {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c := Card{GeneratedAt: now.UTC(), Health: snap.HealthScore, StaleAgents: fl.StaleAgents, Detached: cov.DetachedPrograms, MissingMaps: cov.MissingMapEntries, BlockedEv: rs.Blocked, Headline: snap.Headline}
	score := snap.HealthScore
	if score <= 0 {
		score = 70
	}
	var notes []string
	if fl.StaleAgents > 0 {
		score -= 10 * fl.StaleAgents
		if score < 0 {
			score = 0
		}
		notes = append(notes, "stale agents")
	}
	if cov.DetachedPrograms > 0 {
		score -= 8
		notes = append(notes, "detached programs")
	}
	if cov.MissingMapEntries > 0 {
		score -= 8
		notes = append(notes, "missing maps")
	}
	if rs.Blocked > 20 {
		score -= 5
		notes = append(notes, "elevated blocked events")
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	c.Score = score
	switch {
	case score >= 85:
		c.Band = "green"
	case score >= 60:
		c.Band = "amber"
	default:
		c.Band = "red"
	}
	c.Notes = notes
	return c
}
