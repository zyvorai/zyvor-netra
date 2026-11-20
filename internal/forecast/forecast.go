// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package forecast projects the cluster health score's recent trend forward
// to estimate a "time to breach" a configurable threshold. This is a linear
// heuristic over a coarse, step-function score (internal/health.score deducts
// in 3/5/7/10/15/20-point chunks) — deliberately conservative about when it
// speaks up at all, and never claims high confidence, matching this
// project's existing "conservative heuristics, not statistical claims"
// convention (see internal/health/summary.go).
package forecast

import (
	"fmt"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// MinSamples is the fewest samples Project will attempt a fit over.
	MinSamples = 5
	// MinSpan is the shortest sample span Project will attempt a fit over.
	MinSpan = 2 * time.Minute
	// MaxHorizon bounds how far out a breach may be projected. Beyond this,
	// the linear fit is treated as too speculative to report a number.
	MaxHorizon = 24 * time.Hour
	// minFitQuality is the R² floor below which the fit is called too noisy
	// to project from, even if the slope happens to point at a breach.
	minFitQuality = 0.3
	// mediumConfidenceFitQuality and mediumConfidenceSamples both gate
	// Confidence: "medium" — a tighter fit over more history. Confidence is
	// never anything higher than "medium".
	mediumConfidenceFitQuality = 0.6
	mediumConfidenceSamples    = 10

	// DefaultBreachThreshold is used by callers that don't ask for a
	// specific threshold — the midpoint of the 0-100 health score.
	DefaultBreachThreshold = 50
)

// Project fits an ordinary-least-squares line through samples' HealthScore
// over time and, if the fit is declining and reasonably clean, estimates
// when it would cross breachThreshold. samples must be ordered oldest-first
// (as internal/store.HealthHistory already returns them).
func Project(samples []models.ClusterHealthSample, breachThreshold int, now time.Time) models.HealthTrend {
	out := models.HealthTrend{GeneratedAt: now.UTC(), BreachThreshold: breachThreshold, Samples: len(samples)}
	if len(samples) == 0 {
		out.Note = "no health-history samples recorded yet; history accumulates as something polls the controller (a dashboard, netra-mcp, or the alert poller)"
		return out
	}
	out.CurrentScore = samples[len(samples)-1].HealthScore
	if len(samples) < MinSamples {
		out.Note = fmt.Sprintf("insufficient data: %d sample(s) recorded, need at least %d before projecting a trend", len(samples), MinSamples)
		return out
	}
	span := samples[len(samples)-1].At.Sub(samples[0].At)
	out.SpanSeconds = span.Seconds()
	if span < MinSpan {
		out.Note = fmt.Sprintf("insufficient data: samples span %s, need at least %s before projecting a trend", span.Round(time.Second), MinSpan)
		return out
	}

	slope, intercept, rSquared, t0 := olsFit(samples)
	out.SlopePerHour = slope * 3600

	if slope >= 0 {
		out.Note = "health score is flat or improving over the sampled window; no breach projected"
		return out
	}
	if rSquared < minFitQuality {
		out.Note = "recent health-score samples are too noisy for a reliable linear trend; no breach projected"
		return out
	}

	// intercept + slope*x = breachThreshold, x in seconds since t0.
	breachX := (float64(breachThreshold) - intercept) / slope
	breachAt := t0.Add(time.Duration(breachX * float64(time.Second)))
	remaining := breachAt.Sub(now)

	if remaining <= 0 {
		out.Note = "the linear trend already projects at or below the breach threshold; treat the current score, not this projection, as authoritative"
		zero := 0.0
		out.TimeToBreachSeconds = &zero
		out.Confidence = "low"
		return out
	}
	if remaining > MaxHorizon {
		out.Note = "no near-term breach projected (beyond the 24h horizon this feature reports on)"
		return out
	}

	secs := remaining.Seconds()
	out.TimeToBreachSeconds = &secs
	out.Confidence = "low"
	if rSquared >= mediumConfidenceFitQuality && len(samples) >= mediumConfidenceSamples {
		out.Confidence = "medium"
	}
	out.Note = "linear projection from recent health-score samples — a heuristic trend over a coarse, step-function score, not a statistical guarantee"
	return out
}

// olsFit returns the slope (score/second) and intercept of an ordinary
// least-squares fit of HealthScore against time (seconds since samples[0].At,
// returned as t0 so the caller can convert a fitted x back to a wall-clock
// time), plus the fit's R².
func olsFit(samples []models.ClusterHealthSample) (slope, intercept, rSquared float64, t0 time.Time) {
	t0 = samples[0].At
	n := float64(len(samples))
	var sumX, sumY, sumXY, sumXX float64
	for _, s := range samples {
		x := s.At.Sub(t0).Seconds()
		y := float64(s.HealthScore)
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}
	meanX, meanY := sumX/n, sumY/n
	denom := sumXX - n*meanX*meanX
	if denom == 0 {
		return 0, meanY, 0, t0
	}
	slope = (sumXY - n*meanX*meanY) / denom
	intercept = meanY - slope*meanX

	var ssRes, ssTot float64
	for _, s := range samples {
		x := s.At.Sub(t0).Seconds()
		y := float64(s.HealthScore)
		yHat := intercept + slope*x
		ssRes += (y - yHat) * (y - yHat)
		ssTot += (y - meanY) * (y - meanY)
	}
	if ssTot == 0 {
		rSquared = 1
	} else {
		rSquared = 1 - ssRes/ssTot
	}
	return slope, intercept, rSquared, t0
}
