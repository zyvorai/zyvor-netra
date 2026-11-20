// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package forecast

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func sampleAt(t0 time.Time, offsetSec int, score int) models.ClusterHealthSample {
	return models.ClusterHealthSample{At: t0.Add(time.Duration(offsetSec) * time.Second), HealthScore: score}
}

func TestProjectNoSamples(t *testing.T) {
	out := Project(nil, DefaultBreachThreshold, time.Now())
	if out.TimeToBreachSeconds != nil {
		t.Fatalf("expected no projection with zero samples, got %#v", out)
	}
	if out.Note == "" {
		t.Fatal("expected an explanatory note")
	}
}

func TestProjectTooFewSamples(t *testing.T) {
	t0 := time.Now()
	samples := []models.ClusterHealthSample{sampleAt(t0, 0, 90), sampleAt(t0, 30, 80)}
	out := Project(samples, DefaultBreachThreshold, t0.Add(30*time.Second))
	if out.TimeToBreachSeconds != nil {
		t.Fatalf("expected no projection with %d < %d samples", len(samples), MinSamples)
	}
}

func TestProjectSpanTooShort(t *testing.T) {
	t0 := time.Now()
	var samples []models.ClusterHealthSample
	for i := range MinSamples + 2 {
		samples = append(samples, sampleAt(t0, i*10, 100-i))
	}
	out := Project(samples, DefaultBreachThreshold, t0)
	if out.TimeToBreachSeconds != nil {
		t.Fatalf("expected no projection when span < MinSpan, got %#v", out)
	}
}

func TestProjectFlatTrendNeverProjects(t *testing.T) {
	t0 := time.Now()
	var samples []models.ClusterHealthSample
	for i := range 10 {
		samples = append(samples, sampleAt(t0, i*30, 95)) // constant score
	}
	out := Project(samples, DefaultBreachThreshold, t0.Add(9*30*time.Second))
	if out.TimeToBreachSeconds != nil {
		t.Fatalf("flat trend must never project a breach, got %#v", out)
	}
}

func TestProjectImprovingTrendNeverProjects(t *testing.T) {
	t0 := time.Now()
	var samples []models.ClusterHealthSample
	for i := range 10 {
		samples = append(samples, sampleAt(t0, i*30, 50+i)) // improving
	}
	out := Project(samples, DefaultBreachThreshold, t0.Add(9*30*time.Second))
	if out.TimeToBreachSeconds != nil {
		t.Fatalf("improving trend must never project a breach, got %#v", out)
	}
}

func TestProjectCleanDecliningTrendProjectsBreach(t *testing.T) {
	t0 := time.Now()
	var samples []models.ClusterHealthSample
	for i := range 12 {
		samples = append(samples, sampleAt(t0, i*60, 100-2*i)) // clean linear decline, 2pts/min
	}
	now := t0.Add(11 * 60 * time.Second)
	out := Project(samples, 50, now)
	if out.TimeToBreachSeconds == nil {
		t.Fatalf("expected a projected breach for a clean declining trend, got note=%q", out.Note)
	}
	if out.Confidence == "" || out.Confidence == "high" {
		t.Fatalf("confidence=%q, want low or medium, never high or empty", out.Confidence)
	}
	// score is 78 at now (100-2*11=78); declining 2/min = 120/hr toward 50 breach.
	// remaining points = 78-50 = 28, at 2/min => 14min = 840s.
	if *out.TimeToBreachSeconds < 700 || *out.TimeToBreachSeconds > 1000 {
		t.Fatalf("timeToBreachSeconds=%v, want roughly 840", *out.TimeToBreachSeconds)
	}
}

func TestProjectNoisyFitDeclinesToProject(t *testing.T) {
	t0 := time.Now()
	scores := []int{90, 40, 95, 35, 92, 38, 91, 42, 89, 45, 93, 37}
	var samples []models.ClusterHealthSample
	for i, sc := range scores {
		samples = append(samples, sampleAt(t0, i*60, sc))
	}
	out := Project(samples, 50, t0.Add(11*60*time.Second))
	if out.TimeToBreachSeconds != nil {
		t.Fatalf("expected a noisy fit to decline projecting, got %#v", out)
	}
}

func TestProjectBeyondHorizonDeclinesToProject(t *testing.T) {
	t0 := time.Now()
	var samples []models.ClusterHealthSample
	// Very slow decline: 1 point per hour, sampled every 5 minutes.
	for i := range 12 {
		samples = append(samples, sampleAt(t0, i*300, 100-i)) // ~12pts over 55min => steep enough actually
	}
	// Use a threshold far below current trend reach within 24h to force horizon overflow.
	out := Project(samples, -1000, t0.Add(11*300*time.Second))
	if out.TimeToBreachSeconds != nil {
		t.Fatalf("expected an unreachable-within-horizon threshold to decline projecting, got %#v", out)
	}
}

func TestProjectAlreadyAtOrBelowThreshold(t *testing.T) {
	t0 := time.Now()
	var samples []models.ClusterHealthSample
	for i := range 10 {
		samples = append(samples, sampleAt(t0, i*60, 40-i)) // already below 50 and declining
	}
	now := t0.Add(9 * 60 * time.Second)
	out := Project(samples, 50, now)
	if out.TimeToBreachSeconds == nil || *out.TimeToBreachSeconds != 0 {
		t.Fatalf("expected timeToBreachSeconds=0 when already past threshold, got %#v", out)
	}
}
