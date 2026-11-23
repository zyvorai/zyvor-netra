// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package capacity

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

// series builds n points 10s apart from v0 rising by step per point.
func series(n int, v0, step float64) []Point {
	out := make([]Point, n)
	for i := range out {
		out[i] = Point{T: t0.Unix() + int64(i)*10, V: v0 + float64(i)*step}
	}
	return out
}

func TestProject(t *testing.T) {
	now := t0.Add(time.Hour)
	tests := []struct {
		name     string
		in       Input
		wantETA  bool
		wantSev  string
		noteHas  string
		etaWithn [2]float64 // seconds, inclusive range when wantETA
	}{
		{name: "rising linearly", in: Input{Limit: 100, Points: series(60, 50, 0.2)}, wantETA: true, wantSev: SeverityCritical, etaWithn: [2]float64{1500, 3000}},
		{name: "flat", in: Input{Limit: 100, Points: series(60, 40, 0)}, wantSev: SeverityOK, noteHas: "flat or falling"},
		{name: "falling", in: Input{Limit: 100, Points: series(60, 80, -0.1)}, wantSev: SeverityOK, noteHas: "flat or falling"},
		{name: "already at limit", in: Input{Limit: 100, Points: series(3, 100, 0)}, wantETA: true, wantSev: SeverityCritical, noteHas: "at or above", etaWithn: [2]float64{0, 0}},
		{name: "over limit", in: Input{Limit: 100, Points: series(3, 140, 0)}, wantETA: true, wantSev: SeverityCritical, etaWithn: [2]float64{0, 0}},
		{name: "too few samples", in: Input{Limit: 100, Points: series(5, 10, 1)}, wantSev: SeverityOK, noteHas: "insufficient history"},
		{name: "short span", in: Input{Limit: 100, Points: func() []Point {
			p := series(20, 10, 1)
			for i := range p {
				p[i].T = t0.Unix() + int64(i)
			}
			return p
		}()}, wantSev: SeverityOK, noteHas: "insufficient history"},
		{name: "no samples", in: Input{Limit: 100}, wantSev: SeverityOK, noteHas: "no samples"},
		{name: "zero limit", in: Input{Limit: 0, Points: series(30, 1, 1)}, wantSev: SeverityOK, noteHas: "invalid limit"},
		{name: "negative limit", in: Input{Limit: -5, Points: series(30, 1, 1)}, wantSev: SeverityOK, noteHas: "invalid limit"},
		{name: "infinite limit", in: Input{Limit: math.Inf(1), Points: series(30, 1, 1)}, wantSev: SeverityOK, noteHas: "invalid limit"},
		{name: "beyond horizon", in: Input{Limit: 100, Points: series(60, 1, 0.0005)}, wantSev: SeverityOK, noteHas: "within"},
		{name: "high level without trend", in: Input{Limit: 100, Points: series(60, 96, 0)}, wantSev: SeverityCritical, noteHas: "flat"},
		{name: "warning level without trend", in: Input{Limit: 100, Points: series(60, 88, 0)}, wantSev: SeverityWarning},
		{name: "slow rise gives info", in: Input{Limit: 100, Points: series(60, 50, 0.01)}, wantETA: true, wantSev: SeverityInfo, etaWithn: [2]float64{6 * 3600, 24 * 3600}},
		{name: "recent flat after long rise", in: Input{Limit: 100, Points: func() []Point {
			p := series(60, 10, 0.5)
			for i := 40; i < 60; i++ {
				p[i].V = p[39].V
			}
			return p
		}()}, wantSev: SeverityOK, noteHas: "recent"},
		{name: "nan inf and duplicates dropped", in: Input{Limit: 100, Points: func() []Point {
			p := series(60, 50, 0.2)
			p[5].V = math.NaN()
			p[6].V = math.Inf(1)
			p[7].T = p[6].T // duplicate timestamp
			p[8].T = 0      // invalid timestamp
			return p
		}()}, wantETA: true, wantSev: SeverityCritical, etaWithn: [2]float64{1500, 3000}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := Project(tc.in, now)
			if f.Severity != tc.wantSev {
				t.Fatalf("severity %q want %q (%+v)", f.Severity, tc.wantSev, f)
			}
			if tc.noteHas != "" && !contains(f.Note, tc.noteHas) {
				t.Fatalf("note %q lacks %q", f.Note, tc.noteHas)
			}
			if (f.SecondsToExhaustion != nil) != tc.wantETA {
				t.Fatalf("eta presence %v want %v (%+v)", f.SecondsToExhaustion != nil, tc.wantETA, f)
			}
			if tc.wantETA {
				s := *f.SecondsToExhaustion
				if s < tc.etaWithn[0] || s > tc.etaWithn[1] {
					t.Fatalf("eta %.0fs outside %v", s, tc.etaWithn)
				}
				if f.ExhaustsAt == nil {
					t.Fatal("missing exhaustsAt")
				}
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestNoisyFitIsRefused(t *testing.T) {
	p := series(60, 50, 0)
	for i := range p {
		if i%2 == 0 {
			p[i].V = 20
		} else {
			p[i].V = 80
		}
	}
	p[59].V = 55
	p[58].V = 70
	p[57].V = 40
	f := Project(Input{Limit: 100, Points: p}, t0.Add(time.Hour))
	if f.SecondsToExhaustion != nil {
		t.Fatalf("noisy series produced an eta: %+v", f)
	}
}

func TestHugeSeriesIsBounded(t *testing.T) {
	n := MaxPoints * 3
	p := make([]Point, n)
	for i := range p {
		p[i] = Point{T: t0.Unix() + int64(i), V: float64(i%100) / 10}
	}
	f := Project(Input{Limit: 100, Points: p}, t0)
	if f.Samples != MaxPoints {
		t.Fatalf("samples %d want %d", f.Samples, MaxPoints)
	}
}

func TestBuildOrdersWorstFirstAndCarriesCaveats(t *testing.T) {
	now := t0.Add(time.Hour)
	r := Build([]Input{
		{Node: "b", Resource: "conntrack", Limit: 100, Points: series(60, 10, 0)},
		{Node: "a", Resource: "conntrack", Limit: 100, Points: series(60, 50, 0.1)},
		{Node: "c", Resource: "ephemeral-ports", Limit: 100, Points: series(60, 50, 0.2)},
	}, now)
	if len(r.Forecasts) != 3 || len(r.Caveats) == 0 {
		t.Fatalf("%+v", r)
	}
	if r.Forecasts[0].Node != "c" || r.Forecasts[1].Node != "a" || r.Forecasts[2].Node != "b" {
		t.Fatalf("order %v %v %v", r.Forecasts[0].Node, r.Forecasts[1].Node, r.Forecasts[2].Node)
	}
}

func TestConfidenceNeverAboveMedium(t *testing.T) {
	f := Project(Input{Limit: 100, Points: series(200, 20, 0.1)}, t0.Add(time.Hour))
	if f.Confidence != "medium" {
		t.Fatalf("confidence %q", f.Confidence)
	}
	f = Project(Input{Limit: 100, Points: series(14, 20, 1)}, t0.Add(time.Hour))
	if f.Confidence != "low" && f.Confidence != "" {
		t.Fatalf("confidence %q", f.Confidence)
	}
}
