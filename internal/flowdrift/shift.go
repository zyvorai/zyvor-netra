// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package flowdrift

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

// ShiftSchema names the volume shift report.
const ShiftSchema = "netra-volume-shift/1"

// Volume shift defaults.
const (
	DefaultFactor   = 3.0
	MaxFactor       = 1000.0
	DefaultMinBytes = 10 << 20 // 10 MiB moved in the recent window (or expected, for a drop)
)

// Baseline modes of the volume shift report.
const (
	// ModeAverage compares against the average rate over the whole baseline.
	ModeAverage = "average"
	// ModeSameTime compares against the median of the same time of day on
	// earlier days, so a nightly or business-hours cycle is not a shift.
	ModeSameTime = "same-time"
	// MinSameTimeDays is how many earlier days must be covered before the
	// same-time comparison says anything.
	MinSameTimeDays = 2
)

// ShiftOptions extend Options.
type ShiftOptions struct {
	Options
	Factor   float64 // surge when recent rate >= Factor x baseline rate; drop when <= 1/Factor
	MinBytes uint64
	Mode     string // ModeAverage (default) or ModeSameTime
}

// Shift is one workload and direction whose byte rate moved.
type Shift struct {
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload"`
	Direction string `json:"direction"`
	// Kind is surge or drop; in same-time mode also unusual-time: traffic
	// from a workload that is typically silent at this time of day, for which
	// there is no ratio.
	Kind            string  `json:"kind"`
	RecentBytes     uint64  `json:"recentBytes"`
	BaselineBytes   uint64  `json:"baselineBytes"`
	RecentPerHour   float64 `json:"recentBytesPerHour"`
	BaselinePerHour float64 `json:"baselineBytesPerHour"`
	Ratio           float64 `json:"ratio"` // recent rate over baseline rate
}

// ShiftReport is the volume shift answer.
type ShiftReport struct {
	Schema       string   `json:"schema"`
	Now          string   `json:"now"`
	Recent       Window   `json:"recent"`
	Baseline     Window   `json:"baseline"`
	BaselineSpan int64    `json:"baselineSpanSeconds"`
	Ready        bool     `json:"ready"`
	NotReady     string   `json:"notReadyReason,omitempty"`
	Factor       float64  `json:"factor"`
	BaselineMode string   `json:"baselineMode"`
	BaselineDays int      `json:"baselineDays,omitempty"` // earlier days compared, same-time mode
	MinBytes     uint64   `json:"minBytes"`
	Observed     int      `json:"observedDeltas"`
	Truncated    bool     `json:"truncated"`
	Shifts       []Shift  `json:"shifts"`
	Total        int      `json:"total"`
	Limitations  []string `json:"limitations"`
}

type wlKey struct{ ns, wl, dir string }

// BuildShift flags workloads whose per-direction byte rate in the recent
// window differs from their baseline rate by Factor or more. Workloads with no
// baseline traffic are left to BuildDrift (a rate ratio against zero says
// nothing); a quiet recent window only counts as a drop when the baseline
// predicts at least MinBytes for it. In same-time mode the baseline of a
// workload is the median of what it moved in the same window of the day on
// each earlier day the history covers.
func BuildShift(recs []flowlog.Record, so ShiftOptions) ShiftReport {
	o := so.Options
	o.normalise()
	if so.Factor < 1.5 || so.Factor > MaxFactor {
		so.Factor = DefaultFactor
	}
	if so.MinBytes == 0 {
		so.MinBytes = DefaultMinBytes
	}
	if so.Mode != ModeSameTime {
		so.Mode = ModeAverage
	}
	recentStart := o.Now.Add(-o.Recent)
	baseStart := recentStart.Add(-o.Baseline)
	base, recent, oldest := split(recs, o)
	span, ready, why := readiness(o, oldest, len(base))
	limitations := []string{
		"Rates are bytes per hour of Netra's retained flow deltas; the baseline is a single average over the available history, so a daily or weekly cycle (a nightly batch job, a business-hours service) can look like a surge or a drop. Compare with baseline_mode=same-time before concluding.",
	}
	var days []map[wlKey]uint64
	if so.Mode == ModeSameTime {
		limitations = []string{
			"The baseline is the median of the same time of day on each earlier day the history covers. There is no day-of-week model (a weekly job, or a weekend, can still look like a shift), a day on which nothing at all was recorded is skipped as a collection gap, and with only two or three days the median is weak evidence.",
		}
		var whyDays string
		days, whyDays = sameTimeDays(recs, base, o)
		if ready && whyDays != "" {
			ready, why = false, whyDays
		}
	}
	rep := ShiftReport{
		Schema: ShiftSchema, Now: o.Now.Format(time.RFC3339),
		Recent:       Window{recentStart.Format(time.RFC3339), o.Now.Format(time.RFC3339)},
		Baseline:     Window{baseStart.Format(time.RFC3339), recentStart.Format(time.RFC3339)},
		BaselineSpan: int64(span / time.Second), Ready: ready, NotReady: why, Factor: so.Factor, MinBytes: so.MinBytes,
		Observed: len(base) + len(recent), Truncated: o.Truncated, Shifts: []Shift{},
		BaselineMode: so.Mode, BaselineDays: len(days),
		Limitations: append(limitations,
			"A workload with no baseline traffic is not listed here; a new dependency shows in the dependency drift report.",
			"Advisory only: nothing is applied, blocked or captured.",
		),
	}
	if !ready {
		return rep
	}
	sum := func(rs []flowlog.Record) map[wlKey]uint64 {
		m := map[wlKey]uint64{}
		for _, r := range rs {
			m[wlKey{r.Namespace, workloadOf(r), lower(r.Direction)}] += r.Bytes
		}
		return m
	}
	bm, rm := sum(base), sum(recent)
	bh, rh := span.Hours(), o.Recent.Hours()
	keys := map[wlKey]bool{}
	for k := range bm {
		keys[k] = true
	}
	for k := range rm {
		keys[k] = true
	}
	for k := range keys {
		b, r := bm[k], rm[k]
		if b == 0 {
			continue
		}
		bph, rph := float64(b)/bh, float64(r)/rh
		if so.Mode == ModeSameTime {
			b = medianOf(days, k)
			bph = float64(b) / rh
		}
		s := Shift{Namespace: k.ns, Workload: k.wl, Direction: k.dir, RecentBytes: r, BaselineBytes: b, RecentPerHour: round1(rph), BaselinePerHour: round1(bph)}
		if b == 0 {
			// It talked at other times of day, but typically not at this one.
			if r >= so.MinBytes {
				s.Kind = "unusual-time"
				rep.Shifts = append(rep.Shifts, s)
			}
			continue
		}
		ratio := rph / bph
		s.Ratio = round1(ratio)
		switch {
		case ratio >= so.Factor && r >= so.MinBytes:
			s.Kind = "surge"
		case ratio <= 1/so.Factor && uint64(bph*rh) >= so.MinBytes:
			s.Kind = "drop"
		default:
			continue
		}
		rep.Shifts = append(rep.Shifts, s)
	}
	sort.Slice(rep.Shifts, func(i, j int) bool {
		a, b := rep.Shifts[i], rep.Shifts[j]
		if a.Kind != b.Kind {
			return kindRank[a.Kind] < kindRank[b.Kind]
		}
		da, db := delta(a), delta(b)
		if da != db {
			return da > db
		}
		return fmt.Sprint(a.Namespace, a.Workload, a.Direction) < fmt.Sprint(b.Namespace, b.Workload, b.Direction)
	})
	rep.Total = len(rep.Shifts)
	if len(rep.Shifts) > o.Limit {
		rep.Shifts = rep.Shifts[:o.Limit]
	}
	return rep
}

var kindRank = map[string]int{"surge": 0, "unusual-time": 1, "drop": 2}

// sameTimeDays sums, for each earlier day, the bytes each workload moved in the
// window of the day that matches the recent one. A day counts only when the
// history reaches back to its start (within a tenth of the window) and holds at
// least one record for it. The second result says why the comparison cannot run.
func sameTimeDays(all, base []flowlog.Record, o Options) ([]map[wlKey]uint64, string) {
	const day = 24 * time.Hour
	if o.Recent > day {
		return nil, "the same-time comparison needs a recent window of at most 24h"
	}
	var oldest time.Time
	for _, r := range all {
		if oldest.IsZero() || r.ObservedAt.Before(oldest) {
			oldest = r.ObservedAt
		}
	}
	recentStart := o.Now.Add(-o.Recent)
	baseStart := recentStart.Add(-o.Baseline)
	var out []map[wlKey]uint64
	for k := 1; ; k++ {
		start := recentStart.Add(-time.Duration(k) * day)
		if start.Before(baseStart) {
			break
		}
		if oldest.IsZero() || oldest.After(start.Add(o.Recent/10)) {
			break // older days are further out of reach still
		}
		end := start.Add(o.Recent)
		var m map[wlKey]uint64
		for _, r := range base {
			if r.ObservedAt.Before(start) || !r.ObservedAt.Before(end) {
				continue
			}
			if m == nil {
				m = map[wlKey]uint64{}
			}
			m[wlKey{r.Namespace, workloadOf(r), lower(r.Direction)}] += r.Bytes
		}
		if m != nil {
			out = append(out, m)
		}
	}
	if len(out) < MinSameTimeDays {
		return out, fmt.Sprintf("only %d earlier day(s) cover this time of day, need at least %d", len(out), MinSameTimeDays)
	}
	return out, ""
}

// medianOf is the median bytes one workload moved across the compared days,
// counting a day without it as zero.
func medianOf(days []map[wlKey]uint64, k wlKey) uint64 {
	v := make([]uint64, len(days))
	for i, d := range days {
		v[i] = d[k]
	}
	if len(v) == 0 {
		return 0
	}
	slices.Sort(v)
	mid := len(v) / 2
	if len(v)%2 == 1 {
		return v[mid]
	}
	return v[mid-1] + (v[mid]-v[mid-1])/2
}

// delta is the absolute byte-rate change, the sort key within a kind.
func delta(s Shift) float64 {
	d := s.RecentPerHour - s.BaselinePerHour
	if d < 0 {
		d = -d
	}
	return d
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
