// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package metricexport ships the per-second metrics store to external
// systems: Prometheus remote write (protobuf + in-tree snappy), OTLP/HTTP
// metrics and Graphite plaintext. Exporters only read the store. See
// docs/metrics.md#exporting.
package metricexport

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// Point is one downsampled value of a series on a node.
type Point struct {
	T int64 // unix seconds, end of the bucket
	V float64
}

// Series is one exported series with its points in time order.
type Series struct {
	Node   string
	Series tsdb.Series
	Points []Point
}

// Sink delivers a batch. An error leaves the cursors where they were so the
// same window is retried next cycle (bounded by tier-0 retention).
type Sink interface {
	Name() string
	Send(ctx context.Context, batch []Series) error
}

// Options configures an Exporter.
type Options struct {
	Sources func() []tsdb.Source
	Sink    Sink
	// Resolution is the exported step; points inside a step are averaged.
	// Default 10s, minimum 1s.
	Resolution time.Duration
	// Every is how often a batch is sent. Default Resolution, minimum 1s.
	Every time.Duration
	// Contexts keeps only matching contexts (globs); empty exports all.
	Contexts []string
	// Exclude drops matching contexts after Contexts is applied.
	Exclude []string
	// MaxSeries caps series per batch. Default 20000.
	MaxSeries int
	// MaxLag drops backlog older than this after an outage. Default 15m.
	MaxLag time.Duration
	Log    *slog.Logger
}

// Status is the exporter's self-report.
type Status struct {
	Sink       string    `json:"sink"`
	Sent       uint64    `json:"pointsSent"`
	Batches    uint64    `json:"batches"`
	Failures   uint64    `json:"failures"`
	LastError  string    `json:"lastError,omitempty"`
	LastSend   time.Time `json:"lastSend"`
	Resolution string    `json:"resolution"`
}

// Exporter moves points from the store to a Sink.
type Exporter struct {
	opts     Options
	mu       sync.Mutex
	cursor   map[string]int64 // node|key -> last exported bucket end
	sent     atomic.Uint64
	batches  atomic.Uint64
	failures atomic.Uint64
	lastErr  atomic.Value
	lastSend atomic.Int64
}

// New validates opts and returns an Exporter.
func New(opts Options) (*Exporter, error) {
	if opts.Sink == nil || opts.Sources == nil {
		return nil, fmt.Errorf("metricexport: sink and sources are required")
	}
	if opts.Resolution <= 0 {
		opts.Resolution = 10 * time.Second
	}
	opts.Resolution = max(time.Second, opts.Resolution.Truncate(time.Second))
	if opts.Every <= 0 {
		opts.Every = opts.Resolution
	}
	opts.Every = max(time.Second, opts.Every)
	if opts.MaxSeries <= 0 {
		opts.MaxSeries = 20000
	}
	if opts.MaxLag <= 0 {
		opts.MaxLag = 15 * time.Minute
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	e := &Exporter{opts: opts, cursor: map[string]int64{}}
	e.lastErr.Store("")
	return e, nil
}

func (e *Exporter) wanted(context string) bool {
	if len(e.opts.Contexts) > 0 && !tsdb.MatchAny(e.opts.Contexts, context) {
		return false
	}
	for _, x := range e.opts.Exclude {
		if tsdb.MatchGlob(x, context) {
			return false
		}
	}
	return true
}

// Collect builds the next batch up to now without advancing cursors. The
// returned commit function advances them.
func (e *Exporter) Collect(now time.Time) ([]Series, func()) {
	res := int64(e.opts.Resolution / time.Second)
	// Only complete buckets: the current one is still filling.
	end := now.Unix() - now.Unix()%res
	floor := end - int64(e.opts.MaxLag/time.Second)
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Series
	next := map[string]int64{}
	for _, src := range e.opts.Sources() {
		if src.DB == nil {
			continue
		}
		infos := src.DB.List()
		sort.Slice(infos, func(i, j int) bool { return infos[i].Key < infos[j].Key })
		for _, info := range infos {
			if len(out) >= e.opts.MaxSeries {
				break
			}
			if !e.wanted(info.Series.Context) {
				continue
			}
			ck := src.Node + "|" + info.Key
			from, ok := e.cursor[ck]
			if !ok {
				// New series start with the latest complete bucket.
				from = end - res
			}
			from = max(from, floor)
			if from >= end {
				continue
			}
			pts := src.DB.Points(info.Key, from+1, end)
			if len(pts) == 0 {
				continue
			}
			s := Series{Node: src.Node, Series: info.Series}
			var sum float64
			var n int
			bucket := int64(-1)
			flush := func() {
				if n > 0 {
					s.Points = append(s.Points, Point{T: bucket, V: sum / float64(n)})
				}
				sum, n = 0, 0
			}
			for _, p := range pts {
				if math.IsNaN(p.V) || math.IsInf(p.V, 0) {
					continue
				}
				b := p.T + (res-p.T%res)%res // bucket end, aligned
				if b != bucket {
					flush()
					bucket = b
				}
				sum += p.V
				n++
			}
			flush()
			if len(s.Points) == 0 {
				continue
			}
			out = append(out, s)
			next[ck] = end
		}
	}
	return out, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for k, v := range next {
			e.cursor[k] = v
		}
	}
}

// Once collects and sends one batch.
func (e *Exporter) Once(ctx context.Context, now time.Time) error {
	batch, commit := e.Collect(now)
	if len(batch) == 0 {
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, max(10*time.Second, e.opts.Every))
	defer cancel()
	if err := e.opts.Sink.Send(sctx, batch); err != nil {
		e.failures.Add(1)
		e.lastErr.Store(err.Error())
		return err
	}
	commit()
	var n uint64
	for _, s := range batch {
		n += uint64(len(s.Points))
	}
	e.sent.Add(n)
	e.batches.Add(1)
	e.lastErr.Store("")
	e.lastSend.Store(now.Unix())
	return nil
}

// Run exports until ctx ends.
func (e *Exporter) Run(ctx context.Context) {
	t := time.NewTicker(e.opts.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := e.Once(ctx, now); err != nil {
				e.opts.Log.Warn("metrics export failed; will retry", "sink", e.opts.Sink.Name(), "error", err)
			}
		}
	}
}

// Status reports counters.
func (e *Exporter) Status() Status {
	st := Status{Sink: e.opts.Sink.Name(), Sent: e.sent.Load(), Batches: e.batches.Load(), Failures: e.failures.Load(), LastError: e.lastErr.Load().(string), Resolution: e.opts.Resolution.String()}
	if t := e.lastSend.Load(); t > 0 {
		st.LastSend = time.Unix(t, 0)
	}
	return st
}

// metricName maps a context to a Prometheus-style name: netra_system_cpu.
func metricName(prefix, context string) string {
	var b strings.Builder
	b.WriteString(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "_") {
		b.WriteByte('_')
	}
	for _, r := range context {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// labelName sanitizes a label key for Prometheus.
func labelName(k string) string {
	var b strings.Builder
	for i, r := range k {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || (i > 0 && r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// labelsOf is the label set shared by remote write and OTLP: the series
// labels plus node (instance), chart, dimension and family.
func labelsOf(s Series) [][2]string {
	ls := make([][2]string, 0, len(s.Series.Labels)+4)
	reserved := map[string]bool{"__name__": true, "instance": true, "chart": true, "dimension": true, "family": true}
	for k, v := range s.Series.Labels {
		k = labelName(k)
		if reserved[k] || v == "" {
			continue
		}
		ls = append(ls, [2]string{k, v})
	}
	ls = append(ls, [2]string{"instance", s.Node}, [2]string{"chart", s.Series.Chart}, [2]string{"dimension", s.Series.Dimension})
	if s.Series.Family != "" {
		ls = append(ls, [2]string{"family", s.Series.Family})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i][0] < ls[j][0] })
	return ls
}
