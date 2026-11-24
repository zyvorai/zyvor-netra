// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package flowdrift

import (
	"fmt"
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

// ShiftOptions extend Options.
type ShiftOptions struct {
	Options
	Factor   float64 // surge when recent rate >= Factor x baseline rate; drop when <= 1/Factor
	MinBytes uint64
}

// Shift is one workload and direction whose byte rate moved.
type Shift struct {
	Namespace       string  `json:"namespace,omitempty"`
	Workload        string  `json:"workload"`
	Direction       string  `json:"direction"`
	Kind            string  `json:"kind"` // surge | drop
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
// predicts at least MinBytes for it.
func BuildShift(recs []flowlog.Record, so ShiftOptions) ShiftReport {
	o := so.Options
	o.normalise()
	if so.Factor < 1.5 || so.Factor > MaxFactor {
		so.Factor = DefaultFactor
	}
	if so.MinBytes == 0 {
		so.MinBytes = DefaultMinBytes
	}
	recentStart := o.Now.Add(-o.Recent)
	baseStart := recentStart.Add(-o.Baseline)
	base, recent, oldest := split(recs, o)
	span, ready, why := readiness(o, oldest, len(base))
	rep := ShiftReport{
		Schema: ShiftSchema, Now: o.Now.Format(time.RFC3339),
		Recent:       Window{recentStart.Format(time.RFC3339), o.Now.Format(time.RFC3339)},
		Baseline:     Window{baseStart.Format(time.RFC3339), recentStart.Format(time.RFC3339)},
		BaselineSpan: int64(span / time.Second), Ready: ready, NotReady: why, Factor: so.Factor, MinBytes: so.MinBytes,
		Observed: len(base) + len(recent), Truncated: o.Truncated, Shifts: []Shift{},
		Limitations: []string{
			"Rates are bytes per hour of Netra's retained flow deltas; the baseline is a single average over the available history, so a daily or weekly cycle (a nightly batch job, a business-hours service) can look like a surge or a drop. Compare against the same hour on the dashboard before concluding.",
			"A workload with no baseline traffic is not listed here; a new dependency shows in the dependency drift report.",
			"Advisory only: nothing is applied, blocked or captured.",
		},
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
		ratio := rph / bph
		s := Shift{Namespace: k.ns, Workload: k.wl, Direction: k.dir, RecentBytes: r, BaselineBytes: b, RecentPerHour: round1(rph), BaselinePerHour: round1(bph), Ratio: round1(ratio)}
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
			return a.Kind == "surge"
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
