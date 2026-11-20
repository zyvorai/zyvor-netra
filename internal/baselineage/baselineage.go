// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package baselineage

import (
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type Status struct {
	GeneratedAt        time.Time `json:"generatedAt"`
	BehaviorPresent    bool      `json:"behaviorPresent"`
	BehaviorCapturedAt time.Time `json:"behaviorCapturedAt,omitempty"`
	BehaviorAgeSeconds int64     `json:"behaviorAgeSeconds,omitempty"`
	BehaviorEntries    int       `json:"behaviorEntries"`
	RatePresent        bool      `json:"ratePresent"`
	RateCapturedAt     time.Time `json:"rateCapturedAt,omitempty"`
	RateAgeSeconds     int64     `json:"rateAgeSeconds,omitempty"`
	RateEntries        int       `json:"rateEntries"`
	Stale              bool      `json:"stale"`
	Note               string    `json:"note,omitempty"`
}

func Build(b models.BehaviorBaseline, r models.RateBaseline, now time.Time, staleAfter time.Duration) Status {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if staleAfter <= 0 {
		staleAfter = 24 * time.Hour
	}
	s := Status{GeneratedAt: now.UTC(), BehaviorEntries: len(b.Entries), RateEntries: len(r.Entries)}
	if !b.CapturedAt.IsZero() {
		s.BehaviorPresent = true
		s.BehaviorCapturedAt = b.CapturedAt.UTC()
		s.BehaviorAgeSeconds = int64(now.Sub(b.CapturedAt).Seconds())
	}
	if !r.CapturedAt.IsZero() {
		s.RatePresent = true
		s.RateCapturedAt = r.CapturedAt.UTC()
		s.RateAgeSeconds = int64(now.Sub(r.CapturedAt).Seconds())
	}
	if !s.BehaviorPresent || !s.RatePresent {
		s.Stale = true
		s.Note = "one or both baselines missing"
		return s
	}
	if time.Duration(s.BehaviorAgeSeconds)*time.Second > staleAfter || time.Duration(s.RateAgeSeconds)*time.Second > staleAfter {
		s.Stale = true
		s.Note = "baseline older than threshold"
	}
	return s
}
