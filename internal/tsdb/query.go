// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tsdb

import (
	"errors"
	"math"
	"sort"
	"strings"
	"time"
)

// Source is one node's DB in a multi-node query.
type Source struct {
	Node string
	DB   *DB
}

// Query selects series of one context and reduces them to evenly spaced
// points.
type Query struct {
	Context    string            `json:"context"`
	Charts     []string          `json:"charts,omitempty"`     // globs
	Dimensions []string          `json:"dimensions,omitempty"` // globs
	Nodes      []string          `json:"nodes,omitempty"`      // globs
	Labels     map[string]string `json:"labels,omitempty"`     // exact or glob values
	After      int64             `json:"after"`                // unix seconds; <= 0 means relative to Before
	Before     int64             `json:"before"`               // unix seconds; <= 0 means now plus Before
	Points     int               `json:"points"`
	// Group reduces samples inside one time bucket: avg, min, max, sum,
	// last, p50, p90, p95, p99. Percentiles need tier 0 and fall back to max.
	Group string `json:"group,omitempty"`
	// GroupBy merges series: dimension (default), chart, node, instance
	// (chart and dimension), all, or label:<key>.
	GroupBy string `json:"groupBy,omitempty"`
	// Aggregate merges series that fall in one group: sum, avg, min, max.
	// Default is avg for percentage units and sum otherwise.
	Aggregate string `json:"aggregate,omitempty"`
	// Tier forces a tier (0, 1, 2). Nil picks by time range.
	Tier *int `json:"tier,omitempty"`
}

// ResultDim is one output line.
type ResultDim struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Values      []NullFloat       `json:"values"`
	AnomalyRate []NullFloat       `json:"anomalyRate"`
	Series      int               `json:"series"`
}

// Result is the answer to a Query.
type Result struct {
	Context    string      `json:"context"`
	Title      string      `json:"title,omitempty"`
	Units      string      `json:"units,omitempty"`
	Family     string      `json:"family,omitempty"`
	ChartType  string      `json:"chartType,omitempty"`
	Tier       int         `json:"tier"`
	Interval   int64       `json:"interval"`
	After      int64       `json:"after"`
	Before     int64       `json:"before"`
	Timestamps []int64     `json:"timestamps"`
	Dimensions []ResultDim `json:"dimensions"`
	Matched    int         `json:"matched"`
}

type matched struct {
	node string
	db   *DB
	info SeriesInfo
}

// Normalize resolves relative After/Before against now and fills defaults.
func (q *Query) Normalize(now time.Time) {
	if q.Before <= 0 {
		q.Before = now.Unix() + q.Before
	}
	if q.After <= 0 {
		if q.After == 0 {
			q.After = -600
		}
		q.After = q.Before + q.After
	}
	if q.After >= q.Before {
		q.After = q.Before - 1
	}
	if q.Points <= 0 {
		q.Points = int(min(q.Before-q.After, 600))
	}
	if q.Points > 3000 {
		q.Points = 3000
	}
	if q.Group == "" {
		q.Group = "avg"
	}
	if q.GroupBy == "" {
		q.GroupBy = "dimension"
	}
}

func labelsMatch(want map[string]string, have map[string]string, node string) bool {
	for k, v := range want {
		hv := have[k]
		if k == "node" {
			hv = node
		}
		if !MatchGlob(v, hv) {
			return false
		}
	}
	return true
}

func pickTier(q Query, now int64, retention [3]time.Duration) int {
	if q.Tier != nil && *q.Tier >= 0 && *q.Tier <= 2 {
		return *q.Tier
	}
	if q.After >= now-int64(retention[0]/time.Second) {
		return 0
	}
	if q.After >= now-int64(retention[1]/time.Second) {
		return 1
	}
	return 2
}

// Run executes q over sources.
func Run(sources []Source, q Query, now time.Time) (Result, error) {
	if q.Context == "" {
		return Result{}, errors.New("context is required")
	}
	q.Normalize(now)
	var ms []matched
	for _, src := range sources {
		if src.DB == nil || !MatchAny(q.Nodes, src.Node) {
			continue
		}
		for _, info := range src.DB.List() {
			s := info.Series
			if s.Context != q.Context || !MatchAny(q.Charts, s.Chart) || !MatchAny(q.Dimensions, s.Dimension) || !labelsMatch(q.Labels, s.Labels, src.Node) {
				continue
			}
			if info.LastT != 0 && info.LastT < q.After {
				continue
			}
			ms = append(ms, matched{node: src.Node, db: src.DB, info: info})
		}
	}
	res := Result{Context: q.Context, After: q.After, Before: q.Before, Matched: len(ms)}
	if len(ms) == 0 {
		return res, nil
	}
	first := ms[0].info.Series
	res.Title, res.Units, res.Family, res.ChartType = first.Title, first.Units, first.Family, first.ChartType
	tier := pickTier(q, now.Unix(), ms[0].db.Retention())
	res.Tier = tier
	resolution := []int64{Tier0Resolution, Tier1Resolution, Tier2Resolution}[tier]
	step := (q.Before - q.After + int64(q.Points) - 1) / int64(q.Points)
	step = max(resolution, (step+resolution-1)/resolution*resolution)
	start := q.After - q.After%step
	n := int((q.Before-start)/step) + 1
	res.Interval = step
	res.Timestamps = make([]int64, n)
	for i := range res.Timestamps {
		res.Timestamps[i] = start + int64(i)*step
	}
	agg := q.Aggregate
	if agg == "" {
		agg = "sum"
		if first.Units == "%" || strings.HasPrefix(first.Units, "percent") {
			agg = "avg"
		}
	}

	type group struct {
		dim     ResultDim
		vals    [][]float64
		anom    []uint32
		count   []uint32
		members int
	}
	groups := map[string]*group{}
	var order []string

	// Rollups are fetched per DB in one pass per tier.
	rollups := map[*DB]map[string][]Rollup{}
	if tier > 0 {
		keysByDB := map[*DB][]string{}
		for _, m := range ms {
			keysByDB[m.db] = append(keysByDB[m.db], m.info.Key)
		}
		for db, keys := range keysByDB {
			r, err := db.Rollups(tier, keys, start, q.Before)
			if err != nil {
				return res, err
			}
			rollups[db] = r
		}
	}

	for _, m := range ms {
		name, labels := groupKey(q.GroupBy, m)
		g := groups[name]
		if g == nil {
			g = &group{dim: ResultDim{Name: name, Labels: labels}, vals: make([][]float64, n), anom: make([]uint32, n), count: make([]uint32, n)}
			for i := range g.vals {
				g.vals[i] = nil
			}
			groups[name] = g
			order = append(order, name)
		}
		g.members++
		per := bucketSeries(m, tier, rollups, start, step, n, q)
		for i := 0; i < n; i++ {
			if per.count[i] == 0 {
				continue
			}
			g.vals[i] = append(g.vals[i], per.value[i])
			g.anom[i] += per.anom[i]
			g.count[i] += per.count[i]
		}
	}
	sort.Strings(order)
	for _, name := range order {
		g := groups[name]
		g.dim.Series = g.members
		g.dim.Values = make([]NullFloat, n)
		g.dim.AnomalyRate = make([]NullFloat, n)
		for i := 0; i < n; i++ {
			g.dim.Values[i] = NullFloat(combine(agg, g.vals[i]))
			if g.count[i] == 0 {
				g.dim.AnomalyRate[i] = NullFloat(math.NaN())
			} else {
				g.dim.AnomalyRate[i] = NullFloat(100 * float64(g.anom[i]) / float64(g.count[i]))
			}
		}
		res.Dimensions = append(res.Dimensions, g.dim)
	}
	return res, nil
}

func groupKey(by string, m matched) (string, map[string]string) {
	s := m.info.Series
	switch {
	case by == "chart":
		return s.Chart, map[string]string{"node": m.node}
	case by == "node":
		return m.node, map[string]string{"node": m.node}
	case by == "instance":
		return m.node + "/" + s.Chart + "/" + s.Dimension, map[string]string{"node": m.node, "chart": s.Chart}
	case by == "all":
		return "all", nil
	case strings.HasPrefix(by, "label:"):
		k := strings.TrimPrefix(by, "label:")
		v := s.Labels[k]
		if k == "node" {
			v = m.node
		}
		if v == "" {
			v = "(none)"
		}
		return v, map[string]string{k: v}
	default:
		return s.Dimension, nil
	}
}

type bucketed struct {
	value []float64
	anom  []uint32
	count []uint32
}

func bucketSeries(m matched, tier int, rollups map[*DB]map[string][]Rollup, start, step int64, n int, q Query) bucketed {
	out := bucketed{value: make([]float64, n), anom: make([]uint32, n), count: make([]uint32, n)}
	if tier == 0 {
		vals := make([][]float64, n)
		for _, p := range m.db.Points(m.info.Key, start, q.Before) {
			i := int((p.T - start) / step)
			if i < 0 || i >= n {
				continue
			}
			vals[i] = append(vals[i], p.V)
			out.count[i]++
			if p.Anomalous {
				out.anom[i]++
			}
		}
		for i := range vals {
			if len(vals[i]) > 0 {
				out.value[i] = reduce(q.Group, vals[i])
			}
		}
		return out
	}
	acc := make([]Rollup, n)
	last := make([]float64, n)
	for _, r := range rollups[m.db][m.info.Key] {
		i := int((r.Start - start) / step)
		if i < 0 || i >= n || r.Count == 0 {
			continue
		}
		a := &acc[i]
		if a.Count == 0 {
			a.Min, a.Max = r.Min, r.Max
		} else {
			a.Min, a.Max = math.Min(a.Min, r.Min), math.Max(a.Max, r.Max)
		}
		a.Sum += r.Sum
		a.Count += r.Count
		a.Anomalous += r.Anomalous
		last[i] = r.Avg()
	}
	for i, a := range acc {
		if a.Count == 0 {
			continue
		}
		out.count[i] = a.Count
		out.anom[i] = a.Anomalous
		switch q.Group {
		case "min":
			out.value[i] = a.Min
		case "max", "p50", "p90", "p95", "p99":
			out.value[i] = a.Max
		case "sum":
			out.value[i] = a.Sum
		case "last":
			out.value[i] = last[i]
		default:
			out.value[i] = a.Avg()
		}
	}
	return out
}

func reduce(group string, vals []float64) float64 {
	switch group {
	case "min":
		m := vals[0]
		for _, v := range vals[1:] {
			m = math.Min(m, v)
		}
		return m
	case "max":
		m := vals[0]
		for _, v := range vals[1:] {
			m = math.Max(m, v)
		}
		return m
	case "sum":
		var s float64
		for _, v := range vals {
			s += v
		}
		return s
	case "last":
		return vals[len(vals)-1]
	case "p50", "p90", "p95", "p99":
		var p float64
		switch group {
		case "p50":
			p = 0.5
		case "p90":
			p = 0.9
		case "p95":
			p = 0.95
		default:
			p = 0.99
		}
		return Percentile(vals, p)
	default:
		var s float64
		for _, v := range vals {
			s += v
		}
		return s / float64(len(vals))
	}
}

func combine(agg string, vals []float64) float64 {
	if len(vals) == 0 {
		return math.NaN()
	}
	switch agg {
	case "avg":
		return reduce("avg", vals)
	case "min":
		return reduce("min", vals)
	case "max":
		return reduce("max", vals)
	default:
		return reduce("sum", vals)
	}
}

// Percentile returns the p-quantile (0..1) of vals using nearest rank.
// vals is not modified.
func Percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return math.NaN()
	}
	c := append([]float64(nil), vals...)
	sort.Float64s(c)
	idx := int(math.Ceil(p*float64(len(c)))) - 1
	idx = max(0, min(idx, len(c)-1))
	return c[idx]
}

// ContextInfo describes one context across sources.
type ContextInfo struct {
	Context   string      `json:"context"`
	Family    string      `json:"family,omitempty"`
	Title     string      `json:"title,omitempty"`
	Units     string      `json:"units,omitempty"`
	ChartType string      `json:"chartType,omitempty"`
	Charts    []ChartInfo `json:"charts"`
	FirstT    int64       `json:"firstT"`
	LastT     int64       `json:"lastT"`
}

// ChartInfo is one chart instance of a context.
type ChartInfo struct {
	Node       string            `json:"node"`
	Chart      string            `json:"chart"`
	Labels     map[string]string `json:"labels,omitempty"`
	Dimensions []string          `json:"dimensions"`
}

// Contexts lists every context with its chart instances.
func Contexts(sources []Source, nodes []string) []ContextInfo {
	byCtx := map[string]*ContextInfo{}
	charts := map[string]*ChartInfo{}
	for _, src := range sources {
		if src.DB == nil || !MatchAny(nodes, src.Node) {
			continue
		}
		for _, info := range src.DB.List() {
			s := info.Series
			ci := byCtx[s.Context]
			if ci == nil {
				ci = &ContextInfo{Context: s.Context, FirstT: info.FirstT}
				byCtx[s.Context] = ci
			}
			if s.Family != "" {
				ci.Family, ci.Title, ci.Units, ci.ChartType = s.Family, s.Title, s.Units, s.ChartType
			}
			if info.FirstT != 0 && (ci.FirstT == 0 || info.FirstT < ci.FirstT) {
				ci.FirstT = info.FirstT
			}
			ci.LastT = max(ci.LastT, info.LastT)
			ck := s.Context + "|" + src.Node + "|" + s.Chart
			ch := charts[ck]
			if ch == nil {
				ch = &ChartInfo{Node: src.Node, Chart: s.Chart, Labels: s.Labels}
				charts[ck] = ch
			}
			ch.Dimensions = append(ch.Dimensions, s.Dimension)
		}
	}
	for ck, ch := range charts {
		ctx := ck[:strings.Index(ck, "|")]
		sort.Strings(ch.Dimensions)
		byCtx[ctx].Charts = append(byCtx[ctx].Charts, *ch)
	}
	out := make([]ContextInfo, 0, len(byCtx))
	for _, ci := range byCtx {
		sort.Slice(ci.Charts, func(i, j int) bool {
			if ci.Charts[i].Node != ci.Charts[j].Node {
				return ci.Charts[i].Node < ci.Charts[j].Node
			}
			return ci.Charts[i].Chart < ci.Charts[j].Chart
		})
		out = append(out, *ci)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Context < out[j].Context })
	return out
}
