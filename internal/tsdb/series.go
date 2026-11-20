// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package tsdb is Netra's per-second metrics store: a compressed 1s tier in
// memory, plus per-minute and per-hour rollup tiers kept on disk. It is
// stdlib-only and safe for concurrent use.
package tsdb

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
)

// Series identifies one dimension of one chart instance.
type Series struct {
	Context   string            `json:"context"`
	Chart     string            `json:"chart"`
	Dimension string            `json:"dimension"`
	Family    string            `json:"family,omitempty"`
	Units     string            `json:"units,omitempty"`
	Title     string            `json:"title,omitempty"`
	ChartType string            `json:"chartType,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Key returns the stable identity of the series. Family, units, title and
// chart type are descriptive and do not affect identity.
func (s Series) Key() string {
	var b strings.Builder
	b.WriteString(s.Context)
	b.WriteByte('|')
	b.WriteString(s.Chart)
	b.WriteByte('|')
	b.WriteString(s.Dimension)
	if len(s.Labels) > 0 {
		keys := make([]string, 0, len(s.Labels))
		for k := range s.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteByte('|')
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(s.Labels[k])
		}
	}
	return b.String()
}

// Sample is one value of one series at a unix second.
type Sample struct {
	Series
	T         int64   `json:"t"`
	V         float64 `json:"v"`
	Anomalous bool    `json:"a,omitempty"`
}

// Point is a decoded tier-0 value.
type Point struct {
	T         int64
	V         float64
	Anomalous bool
}

// Rollup aggregates the samples of one series inside one tier interval.
type Rollup struct {
	Start     int64   `json:"start"`
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
	Sum       float64 `json:"sum"`
	Count     uint32  `json:"count"`
	Anomalous uint32  `json:"anomalous"`
}

func (r *Rollup) add(v float64, anomalous bool) {
	if r.Count == 0 {
		r.Min, r.Max = v, v
	} else {
		r.Min = math.Min(r.Min, v)
		r.Max = math.Max(r.Max, v)
	}
	r.Sum += v
	r.Count++
	if anomalous {
		r.Anomalous++
	}
}

// Avg is the mean of the rollup, or NaN when empty.
func (r Rollup) Avg() float64 {
	if r.Count == 0 {
		return math.NaN()
	}
	return r.Sum / float64(r.Count)
}

// NullFloat marshals NaN and infinities as JSON null.
type NullFloat float64

func (f NullFloat) MarshalJSON() ([]byte, error) {
	v := float64(f)
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return []byte("null"), nil
	}
	return json.Marshal(v)
}

func (f *NullFloat) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*f = NullFloat(math.NaN())
		return nil
	}
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*f = NullFloat(v)
	return nil
}

// MatchGlob reports whether s matches a pattern where '*' matches any run of
// characters. An empty pattern matches everything.
func MatchGlob(pattern, s string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// MatchAny reports whether s matches any pattern. No patterns match all.
func MatchAny(patterns []string, s string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if MatchGlob(p, s) {
			return true
		}
	}
	return false
}
