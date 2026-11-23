// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package capacity forecasts when a bounded kernel resource (the conntrack
// table, the ephemeral port range) will run out, from utilization series the
// per-second metrics platform already stores. It is a pure function over
// points: it reads nothing, writes nothing and never touches a sysctl. Like
// internal/forecast it is deliberately conservative: a linear fit, a second
// look at the most recent samples, and silence when the two disagree.
package capacity

import (
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	// MinSamples and MinSpan are the least history Project will fit.
	MinSamples = 12
	MinSpan    = 5 * time.Minute
	// MaxPoints bounds the work done per series; older points are dropped.
	MaxPoints = 20000
	// MaxHorizon bounds how far out an exhaustion is reported. A fit that
	// hits the limit later than this is "not within the horizon".
	MaxHorizon = 72 * time.Hour
	// minFit is the R-squared floor below which the fit is too noisy.
	minFit = 0.3
	// mediumFit and mediumSamples gate Confidence "medium". Confidence is
	// never higher than that.
	mediumFit     = 0.6
	mediumSamples = 30
)

// Severity values, most severe last.
const (
	SeverityOK       = "ok"
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Point is one utilization sample.
type Point struct {
	T int64   // unix seconds
	V float64 // same units as Limit
}

// Input is one series to forecast.
type Input struct {
	Node     string
	Resource string
	Units    string
	Limit    float64 // the value at which the resource is exhausted (100 for %)
	Points   []Point
}

// Forecast is the answer for one series.
type Forecast struct {
	Node                string     `json:"node"`
	Resource            string     `json:"resource"`
	Units               string     `json:"units,omitempty"`
	Limit               float64    `json:"limit"`
	Current             float64    `json:"current"`
	Samples             int        `json:"samples"`
	SpanSeconds         float64    `json:"spanSeconds"`
	SlopePerHour        float64    `json:"slopePerHour"`
	RecentSlopePerHour  float64    `json:"recentSlopePerHour"`
	RSquared            float64    `json:"rSquared"`
	SecondsToExhaustion *float64   `json:"secondsToExhaustion,omitempty"`
	ExhaustsAt          *time.Time `json:"exhaustsAt,omitempty"`
	Severity            string     `json:"severity"`
	Confidence          string     `json:"confidence,omitempty"`
	Note                string     `json:"note,omitempty"`
}

// Report is a set of forecasts, worst first.
type Report struct {
	GeneratedAt time.Time  `json:"generatedAt"`
	Forecasts   []Forecast `json:"forecasts"`
	Caveats     []string   `json:"caveats"`
}

// Caveats are returned with every report.
func Caveats() []string {
	return []string{
		"A linear fit over recent history: a step change (a deploy, a scan, a retry storm) breaks it. Treat the time as an order of magnitude, not a deadline.",
		"No forecast is made from a flat or falling recent trend, from a noisy fit, or from less than 12 samples over 5 minutes.",
		"Ephemeral-port utilization counts the host's own sockets per destination. Ports held by SNAT in the conntrack table of a router or node-port path are not visible to it.",
		"Read-only: nothing here changes a sysctl or any rule. Raising a limit is an operator decision with a memory cost.",
	}
}

// sanitize drops non-finite values and out-of-order or duplicate timestamps
// and keeps at most MaxPoints of the newest points.
func sanitize(in []Point) []Point {
	out := make([]Point, 0, len(in))
	for _, p := range in {
		if math.IsNaN(p.V) || math.IsInf(p.V, 0) || p.T <= 0 {
			continue
		}
		if n := len(out); n > 0 && p.T <= out[n-1].T {
			continue
		}
		out = append(out, p)
	}
	if len(out) > MaxPoints {
		out = out[len(out)-MaxPoints:]
	}
	return out
}

// ols fits v = a + b*t (t in hours since the first point) and returns the
// slope per hour and R-squared.
func ols(pts []Point) (slope, r2 float64) {
	n := float64(len(pts))
	if n < 2 {
		return 0, 0
	}
	t0 := pts[0].T
	var sx, sy, sxx, sxy, syy float64
	for _, p := range pts {
		x := float64(p.T-t0) / 3600
		sx += x
		sy += p.V
		sxx += x * x
		sxy += x * p.V
		syy += p.V * p.V
	}
	den := n*sxx - sx*sx
	if den <= 0 {
		return 0, 0
	}
	slope = (n*sxy - sx*sy) / den
	vden := n*syy - sy*sy
	if vden <= 0 {
		return slope, 0 // a perfectly flat series has no variance to explain
	}
	r := (n*sxy - sx*sy) / math.Sqrt(den*vden)
	return slope, r * r
}

// Project forecasts one series.
func Project(in Input, now time.Time) Forecast {
	f := Forecast{Node: in.Node, Resource: in.Resource, Units: in.Units, Limit: in.Limit, Severity: SeverityOK}
	if !(in.Limit > 0) || math.IsInf(in.Limit, 0) {
		f.Note = "invalid limit; no forecast"
		return f
	}
	pts := sanitize(in.Points)
	f.Samples = len(pts)
	if len(pts) == 0 {
		f.Note = "no samples"
		return f
	}
	last := pts[len(pts)-1]
	f.Current = last.V
	f.SpanSeconds = float64(last.T - pts[0].T)
	level := levelSeverity(f.Current / in.Limit)
	f.Severity = level
	if f.Current >= in.Limit {
		zero := 0.0
		at := now.UTC()
		f.SecondsToExhaustion, f.ExhaustsAt = &zero, &at
		f.Severity = SeverityCritical
		f.Note = "already at or above the limit"
		return f
	}
	if len(pts) < MinSamples || time.Duration(f.SpanSeconds)*time.Second < MinSpan {
		f.Note = fmt.Sprintf("insufficient history: %d samples over %s, need %d over %s", len(pts), time.Duration(f.SpanSeconds)*time.Second, MinSamples, MinSpan)
		return f
	}
	var r2 float64
	f.SlopePerHour, r2 = ols(pts)
	f.RSquared = r2
	recent := pts[len(pts)*2/3:]
	f.RecentSlopePerHour, _ = ols(recent)
	if f.SlopePerHour <= 0 {
		f.Note = "flat or falling trend"
		return f
	}
	if f.RecentSlopePerHour <= 0 {
		f.Note = "the long trend rises but the most recent samples are flat or falling; no forecast"
		return f
	}
	if r2 < minFit {
		f.Note = fmt.Sprintf("trend is too noisy to project (R-squared %.2f)", r2)
		return f
	}
	head := in.Limit - f.Current
	hours := math.Min(head/f.SlopePerHour, head/f.RecentSlopePerHour)
	secs := hours * 3600
	if secs > MaxHorizon.Seconds() || math.IsInf(secs, 0) || math.IsNaN(secs) {
		f.Note = fmt.Sprintf("not projected to be exhausted within %s", MaxHorizon)
		return f
	}
	at := now.UTC().Add(time.Duration(secs * float64(time.Second)))
	f.SecondsToExhaustion, f.ExhaustsAt = &secs, &at
	f.Confidence = "low"
	if r2 >= mediumFit && len(pts) >= mediumSamples {
		f.Confidence = "medium"
	}
	if s := etaSeverity(secs); rank(s) > rank(f.Severity) {
		f.Severity = s
	}
	return f
}

func levelSeverity(frac float64) string {
	switch {
	case frac >= 0.95:
		return SeverityCritical
	case frac >= 0.85:
		return SeverityWarning
	}
	return SeverityOK
}

func etaSeverity(secs float64) string {
	switch {
	case secs < 3600:
		return SeverityCritical
	case secs < 6*3600:
		return SeverityWarning
	case secs < 24*3600:
		return SeverityInfo
	}
	return SeverityOK
}

func rank(s string) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// Build forecasts every input and orders the result worst first, then by
// time to exhaustion, then by node and resource.
func Build(inputs []Input, now time.Time) Report {
	r := Report{GeneratedAt: now.UTC(), Forecasts: make([]Forecast, 0, len(inputs)), Caveats: Caveats()}
	for _, in := range inputs {
		r.Forecasts = append(r.Forecasts, Project(in, now))
	}
	sort.SliceStable(r.Forecasts, func(i, j int) bool {
		a, b := r.Forecasts[i], r.Forecasts[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) > rank(b.Severity)
		}
		ea, eb := eta(a), eta(b)
		if ea != eb {
			return ea < eb
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Resource < b.Resource
	})
	return r
}

func eta(f Forecast) float64 {
	if f.SecondsToExhaustion == nil {
		return math.MaxFloat64
	}
	return *f.SecondsToExhaustion
}
