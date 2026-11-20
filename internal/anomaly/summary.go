// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package anomaly

import (
	"math"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// NodeRate is a node's anomaly rate over a window.
type NodeRate struct {
	Node        string          `json:"node"`
	AnomalyRate float64         `json:"anomalyRate"` // percent of samples
	Dimensions  int             `json:"dimensions"`
	Anomalous   int             `json:"anomalousDimensions"`
	Timeline    []TimelinePoint `json:"timeline,omitempty"`
}

// TimelinePoint is the node anomaly rate in one bucket.
type TimelinePoint struct {
	T    int64          `json:"t"`
	Rate tsdb.NullFloat `json:"rate"`
}

// Ranked is one dimension ordered by how anomalous or changed it is.
type Ranked struct {
	Node        string            `json:"node"`
	Context     string            `json:"context"`
	Chart       string            `json:"chart"`
	Dimension   string            `json:"dimension"`
	Units       string            `json:"units,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	AnomalyRate float64           `json:"anomalyRate"`
	// Score is the anomaly rate for plain ranking, or the two-sample
	// Kolmogorov-Smirnov statistic (0..1) for highlight correlation.
	Score float64 `json:"score"`
}

// Summary answers GET /api/v1/metrics/anomalies.
type Summary struct {
	After           int64      `json:"after"`
	Before          int64      `json:"before"`
	Nodes           []NodeRate `json:"nodes"`
	Ranked          []Ranked   `json:"ranked"`
	HighlightAfter  int64      `json:"highlightAfter,omitempty"`
	HighlightBefore int64      `json:"highlightBefore,omitempty"`
	Correlated      []Ranked   `json:"correlated,omitempty"`
}

type counts struct{ anom, total int }

// seriesCounts returns anomalous and total sample counts plus per-bucket
// counts, using tier 0 inside its retention and tier 1 rollups otherwise.
func seriesCounts(db *tsdb.DB, info tsdb.SeriesInfo, after, before int64, now time.Time, buckets int) (counts, []counts) {
	var c counts
	per := make([]counts, buckets)
	step := max(1, (before-after+int64(buckets)-1)/int64(buckets))
	add := func(t int64, anom, total int) {
		c.anom += anom
		c.total += total
		if i := int((t - after) / step); i >= 0 && i < buckets {
			per[i].anom += anom
			per[i].total += total
		}
	}
	if after >= now.Unix()-int64(db.Retention()[0]/time.Second) {
		for _, p := range db.Points(info.Key, after, before) {
			a := 0
			if p.Anomalous {
				a = 1
			}
			add(p.T, a, 1)
		}
		return c, per
	}
	rs, err := db.Rollups(1, []string{info.Key}, after, before)
	if err != nil {
		return c, per
	}
	for _, r := range rs[info.Key] {
		add(r.Start, int(r.Anomalous), int(r.Count))
	}
	return c, per
}

// Summarize computes per-node anomaly rates, a timeline and the most
// anomalous dimensions in [after, before].
func Summarize(sources []tsdb.Source, nodes []string, after, before int64, top int, now time.Time) Summary {
	if top <= 0 {
		top = 30
	}
	const buckets = 60
	sum := Summary{After: after, Before: before}
	var ranked []Ranked
	step := max(1, (before-after+buckets-1)/buckets)
	for _, src := range sources {
		if src.DB == nil || !tsdb.MatchAny(nodes, src.Node) {
			continue
		}
		nr := NodeRate{Node: src.Node}
		var total counts
		per := make([]counts, buckets)
		for _, info := range src.DB.List() {
			if info.LastT != 0 && info.LastT < after {
				continue
			}
			c, pb := seriesCounts(src.DB, info, after, before, now, buckets)
			if c.total == 0 {
				continue
			}
			nr.Dimensions++
			total.anom += c.anom
			total.total += c.total
			for i := range per {
				per[i].anom += pb[i].anom
				per[i].total += pb[i].total
			}
			if c.anom > 0 {
				nr.Anomalous++
				rate := 100 * float64(c.anom) / float64(c.total)
				s := info.Series
				ranked = append(ranked, Ranked{Node: src.Node, Context: s.Context, Chart: s.Chart, Dimension: s.Dimension, Units: s.Units, Labels: s.Labels, AnomalyRate: rate, Score: rate})
			}
		}
		if total.total > 0 {
			nr.AnomalyRate = 100 * float64(total.anom) / float64(total.total)
		}
		for i, b := range per {
			p := TimelinePoint{T: after + int64(i)*step, Rate: tsdb.NullFloat(math.NaN())}
			if b.total > 0 {
				p.Rate = tsdb.NullFloat(100 * float64(b.anom) / float64(b.total))
			}
			nr.Timeline = append(nr.Timeline, p)
		}
		sum.Nodes = append(sum.Nodes, nr)
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Score != ranked[j].Score {
			return ranked[i].Score > ranked[j].Score
		}
		return ranked[i].Chart+ranked[i].Dimension < ranked[j].Chart+ranked[j].Dimension
	})
	if len(ranked) > top {
		ranked = ranked[:top]
	}
	sum.Ranked = ranked
	return sum
}

// Correlate ranks dimensions by how much their value distribution in the
// highlighted window differs from the baseline window just before it (four
// times as long), using the two-sample Kolmogorov-Smirnov statistic. This is
// the "what changed here" view.
func Correlate(sources []tsdb.Source, nodes []string, hAfter, hBefore int64, top int, now time.Time) []Ranked {
	if top <= 0 {
		top = 30
	}
	span := hBefore - hAfter
	if span <= 0 {
		return nil
	}
	bAfter := hAfter - 4*span
	var out []Ranked
	for _, src := range sources {
		if src.DB == nil || !tsdb.MatchAny(nodes, src.Node) {
			continue
		}
		useTier0 := bAfter >= now.Unix()-int64(src.DB.Retention()[0]/time.Second)
		for _, info := range src.DB.List() {
			if info.LastT != 0 && info.LastT < hAfter {
				continue
			}
			var base, high []float64
			var anom, total int
			if useTier0 {
				for _, p := range src.DB.Points(info.Key, bAfter, hBefore) {
					if p.T < hAfter {
						base = append(base, p.V)
						continue
					}
					high = append(high, p.V)
					total++
					if p.Anomalous {
						anom++
					}
				}
			} else {
				rs, err := src.DB.Rollups(1, []string{info.Key}, bAfter, hBefore)
				if err != nil {
					continue
				}
				for _, r := range rs[info.Key] {
					if r.Start < hAfter {
						base = append(base, r.Avg())
						continue
					}
					high = append(high, r.Avg())
					total += int(r.Count)
					anom += int(r.Anomalous)
				}
			}
			if len(base) < 3 || len(high) < 3 {
				continue
			}
			d := KS(base, high)
			if d <= 0 {
				continue
			}
			s := info.Series
			r := Ranked{Node: src.Node, Context: s.Context, Chart: s.Chart, Dimension: s.Dimension, Units: s.Units, Labels: s.Labels, Score: d}
			if total > 0 {
				r.AnomalyRate = 100 * float64(anom) / float64(total)
			}
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].AnomalyRate > out[j].AnomalyRate
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

// KS is the two-sample Kolmogorov-Smirnov statistic: the largest distance
// between the empirical distribution functions of a and b.
func KS(a, b []float64) float64 {
	x := append([]float64(nil), a...)
	y := append([]float64(nil), b...)
	sort.Float64s(x)
	sort.Float64s(y)
	var i, j int
	var d float64
	for i < len(x) && j < len(y) {
		v := math.Min(x[i], y[j])
		for i < len(x) && x[i] <= v {
			i++
		}
		for j < len(y) && y[j] <= v {
			j++
		}
		d = math.Max(d, math.Abs(float64(i)/float64(len(x))-float64(j)/float64(len(y))))
	}
	return d
}
