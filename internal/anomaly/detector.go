// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package anomaly is unsupervised per-metric anomaly detection in the style
// of Netdata's ML: every dimension gets its own k-means model (k=2) trained
// on feature vectors built from its recent differenced and smoothed values.
// A new sample is anomalous when its distance to the nearest cluster centre
// exceeds the 99th percentile of the training distances. Stdlib only.
package anomaly

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// Options tunes training. Zero values pick the defaults.
type Options struct {
	TrainWindow time.Duration // default 6h, clipped to the data available
	TrainEvery  time.Duration // default 3h
	// YoungEvery retrains models trained on less than a full window, so a
	// fresh node gets useful models within minutes. Default 10m.
	YoungEvery     time.Duration
	MinTrainPoints int     // default 300
	MaxTrainPoints int     // feature vectors per training, default 3600
	Lag            int     // default 5, so feature vectors have 6 values
	Smooth         int     // default 3
	Quantile       float64 // default 0.99
	// PerCycle caps models trained per Run tick so training cost is spread
	// across the interval. Default 200.
	PerCycle int
}

func (o *Options) defaults() {
	if o.TrainWindow <= 0 {
		o.TrainWindow = 6 * time.Hour
	}
	if o.TrainEvery <= 0 {
		o.TrainEvery = 3 * time.Hour
	}
	if o.YoungEvery <= 0 {
		o.YoungEvery = 10 * time.Minute
	}
	if o.MinTrainPoints <= 0 {
		o.MinTrainPoints = 300
	}
	if o.MaxTrainPoints <= 0 {
		o.MaxTrainPoints = 3600
	}
	if o.Lag <= 0 {
		o.Lag = 5
	}
	if o.Smooth <= 0 {
		o.Smooth = 3
	}
	if o.Quantile <= 0 || o.Quantile >= 1 {
		o.Quantile = 0.99
	}
	if o.PerCycle <= 0 {
		o.PerCycle = 200
	}
}

type model struct {
	centers   [2][]float64
	threshold float64
	trainedAt time.Time
	span      time.Duration
	points    int
}

type recent struct {
	vals []float64 // ring of the last Lag+Smooth+1 raw values
	n    int
	pos  int
}

// Detector holds one model per series key.
type Detector struct {
	opts   Options
	mu     sync.Mutex
	models map[string]*model
	recent map[string]*recent
	retry  map[string]time.Time
	stats  Stats
}

// Stats summarizes the detector.
type Stats struct {
	Models     int       `json:"models"`
	Trained    uint64    `json:"trained"`
	Scored     uint64    `json:"scored"`
	Anomalous  uint64    `json:"anomalous"`
	LastTrainT time.Time `json:"lastTrain"`
}

// New returns a detector.
func New(opts Options) *Detector {
	opts.defaults()
	return &Detector{opts: opts, models: map[string]*model{}, recent: map[string]*recent{}, retry: map[string]time.Time{}}
}

func (d *Detector) window() int { return d.opts.Lag + d.opts.Smooth + 1 }

// features turns raw values into differenced, smoothed, lagged vectors.
func features(raw []float64, lag, smooth int) [][]float64 {
	if len(raw) < lag+smooth+1 {
		return nil
	}
	diffs := make([]float64, len(raw)-1)
	for i := 1; i < len(raw); i++ {
		diffs[i-1] = raw[i] - raw[i-1]
	}
	sm := make([]float64, len(diffs)-smooth+1)
	var acc float64
	for i, v := range diffs {
		acc += v
		if i >= smooth {
			acc -= diffs[i-smooth]
		}
		if i >= smooth-1 {
			sm[i-smooth+1] = acc / float64(smooth)
		}
	}
	out := make([][]float64, 0, len(sm)-lag)
	for i := lag; i < len(sm); i++ {
		v := make([]float64, lag+1)
		copy(v, sm[i-lag:i+1])
		out = append(out, v)
	}
	return out
}

func dist(a, b []float64) float64 {
	var s float64
	for i := range a {
		d := a[i] - b[i]
		s += d * d
	}
	return math.Sqrt(s)
}

func (m *model) score(f []float64) float64 {
	return math.Min(dist(f, m.centers[0]), dist(f, m.centers[1]))
}

// kmeans2 clusters feats into two groups. Initial centres are the vector
// closest to the origin and the one farthest from it, which is deterministic.
func kmeans2(feats [][]float64) [2][]float64 {
	dim := len(feats[0])
	zero := make([]float64, dim)
	lo, hi := 0, 0
	for i, f := range feats {
		if dist(f, zero) < dist(feats[lo], zero) {
			lo = i
		}
		if dist(f, zero) > dist(feats[hi], zero) {
			hi = i
		}
	}
	c := [2][]float64{append([]float64(nil), feats[lo]...), append([]float64(nil), feats[hi]...)}
	assign := make([]int, len(feats))
	for iter := 0; iter < 20; iter++ {
		changed := false
		for i, f := range feats {
			k := 0
			if dist(f, c[1]) < dist(f, c[0]) {
				k = 1
			}
			if assign[i] != k {
				changed = true
				assign[i] = k
			}
		}
		var sums [2][]float64
		var counts [2]int
		for k := range sums {
			sums[k] = make([]float64, dim)
		}
		for i, f := range feats {
			k := assign[i]
			counts[k]++
			for j, v := range f {
				sums[k][j] += v
			}
		}
		for k := range c {
			if counts[k] == 0 {
				continue
			}
			for j := range c[k] {
				c[k][j] = sums[k][j] / float64(counts[k])
			}
		}
		if !changed && iter > 0 {
			break
		}
	}
	return c
}

// TrainSeries fits a model to raw values covering span. It reports false
// when there is not enough data.
func (d *Detector) TrainSeries(key string, raw []float64, span time.Duration, now time.Time) bool {
	feats := features(raw, d.opts.Lag, d.opts.Smooth)
	if len(feats) < d.opts.MinTrainPoints {
		return false
	}
	if len(feats) > d.opts.MaxTrainPoints {
		stride := float64(len(feats)) / float64(d.opts.MaxTrainPoints)
		sub := make([][]float64, 0, d.opts.MaxTrainPoints)
		for i := 0; i < d.opts.MaxTrainPoints; i++ {
			sub = append(sub, feats[int(float64(i)*stride)])
		}
		feats = sub
	}
	m := &model{centers: kmeans2(feats), trainedAt: now, span: span, points: len(feats)}
	scores := make([]float64, len(feats))
	for i, f := range feats {
		scores[i] = m.score(f)
	}
	sort.Float64s(scores)
	idx := int(math.Ceil(d.opts.Quantile*float64(len(scores)))) - 1
	m.threshold = scores[max(0, min(idx, len(scores)-1))]
	// A flat training window has threshold 0; any movement is then
	// anomalous, which is the intended reading of "this never changes".
	d.mu.Lock()
	d.models[key] = m
	d.stats.Trained++
	d.stats.LastTrainT = now
	d.mu.Unlock()
	return true
}

// Annotate updates each series' recent values and sets Anomalous on samples
// whose series has a model and whose score is above its threshold.
func (d *Detector) Annotate(samples []tsdb.Sample) {
	w := d.window()
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range samples {
		key := samples[i].Key()
		r := d.recent[key]
		if r == nil {
			r = &recent{vals: make([]float64, w)}
			d.recent[key] = r
		}
		r.vals[r.pos] = samples[i].V
		r.pos = (r.pos + 1) % w
		if r.n < w {
			r.n++
		}
		m := d.models[key]
		if m == nil || r.n < w {
			continue
		}
		ordered := make([]float64, w)
		for j := 0; j < w; j++ {
			ordered[j] = r.vals[(r.pos+j)%w]
		}
		f := features(ordered, d.opts.Lag, d.opts.Smooth)
		if len(f) == 0 {
			continue
		}
		d.stats.Scored++
		if m.score(f[len(f)-1]) > m.threshold {
			samples[i].Anomalous = true
			d.stats.Anomalous++
		}
	}
}

// due reports whether key needs (re)training at now.
func (d *Detector) due(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if until, ok := d.retry[key]; ok && now.Before(until) {
		return false
	}
	m := d.models[key]
	if m == nil {
		return true
	}
	every := d.opts.TrainEvery
	if m.span < d.opts.TrainWindow*9/10 {
		every = d.opts.YoungEvery
	}
	return now.Sub(m.trainedAt) >= every
}

// TrainDue trains up to limit due models from db, oldest model first.
func (d *Detector) TrainDue(db *tsdb.DB, now time.Time, limit int) int {
	infos := db.List()
	type cand struct {
		key string
		at  time.Time
	}
	var cands []cand
	d.mu.Lock()
	for _, info := range infos {
		var at time.Time
		if m := d.models[info.Key]; m != nil {
			at = m.trainedAt
		}
		cands = append(cands, cand{info.Key, at})
	}
	d.mu.Unlock()
	sort.Slice(cands, func(i, j int) bool { return cands[i].at.Before(cands[j].at) })
	n := 0
	after := now.Add(-d.opts.TrainWindow).Unix()
	for _, c := range cands {
		if n >= limit {
			break
		}
		if !d.due(c.key, now) {
			continue
		}
		pts := db.Points(c.key, after, now.Unix())
		if len(pts) == 0 {
			continue
		}
		raw := make([]float64, len(pts))
		for i, p := range pts {
			raw[i] = p.V
		}
		span := time.Duration(pts[len(pts)-1].T-pts[0].T) * time.Second
		if d.TrainSeries(c.key, raw, span, now) {
			n++
		} else {
			// Not enough data yet: retry in a minute rather than every tick.
			d.mu.Lock()
			d.retry[c.key] = now.Add(time.Minute)
			d.mu.Unlock()
		}
	}
	d.prune(infos)
	return n
}

// prune drops models and buffers for series no longer in the store.
func (d *Detector) prune(infos []tsdb.SeriesInfo) {
	live := make(map[string]bool, len(infos))
	for _, i := range infos {
		live[i.Key] = true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.models {
		if !live[k] {
			delete(d.models, k)
		}
	}
	for k := range d.recent {
		if !live[k] {
			delete(d.recent, k)
		}
	}
	for k := range d.retry {
		if !live[k] {
			delete(d.retry, k)
		}
	}
}

// Run trains due models every 10 seconds until ctx ends.
func (d *Detector) Run(ctx context.Context, db *tsdb.DB) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.TrainDue(db, now, d.opts.PerCycle)
		}
	}
}

// Stats returns detector counters.
func (d *Detector) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.stats
	st.Models = len(d.models)
	return st
}
