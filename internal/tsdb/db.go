// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package tsdb

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Tier resolutions in seconds.
const (
	Tier0Resolution int64 = 1
	Tier1Resolution int64 = 60
	Tier2Resolution int64 = 3600
)

// ErrOutOfOrder is returned when a sample is not newer than the last sample
// of its series.
var ErrOutOfOrder = errors.New("tsdb: sample out of order")

// ErrSeriesLimit is returned when a new series would exceed MaxSeries.
var ErrSeriesLimit = errors.New("tsdb: series limit reached")

// Options configures a DB. Zero values pick the defaults.
type Options struct {
	// Dir holds the rollup segments and the series index. Empty keeps the
	// rollup tiers in a capped in-memory ring instead.
	Dir            string
	Tier0Retention time.Duration // default 1h
	Tier1Retention time.Duration // default 14d
	Tier2Retention time.Duration // default 365d
	// DiskQuotaBytes caps tier 1 plus tier 2 on disk. Tier 1 gets 80%.
	DiskQuotaBytes int64 // default 1 GiB
	MaxSeries      int   // default 50000
	// MemTier1Rows and MemTier2Rows cap the in-memory rollup rings per
	// series when Dir is empty.
	MemTier1Rows int // default 1440 (one day)
	MemTier2Rows int // default 168 (one week)
}

func (o *Options) defaults() {
	if o.Tier0Retention <= 0 {
		o.Tier0Retention = time.Hour
	}
	if o.Tier1Retention <= 0 {
		o.Tier1Retention = 14 * 24 * time.Hour
	}
	if o.Tier2Retention <= 0 {
		o.Tier2Retention = 365 * 24 * time.Hour
	}
	if o.DiskQuotaBytes <= 0 {
		o.DiskQuotaBytes = 1 << 30
	}
	if o.MaxSeries <= 0 {
		o.MaxSeries = 50000
	}
	if o.MemTier1Rows <= 0 {
		o.MemTier1Rows = 1440
	}
	if o.MemTier2Rows <= 0 {
		o.MemTier2Rows = 168
	}
}

type series struct {
	mu     sync.Mutex
	id     uint32
	meta   Series
	chunks []*chunk
	firstT int64
	lastT  int64
	lastV  float64
	lastA  bool
	agg    [2]Rollup
}

// DB is a per-node metrics store.
type DB struct {
	opts   Options
	mu     sync.RWMutex
	byKey  map[string]*series
	byID   map[uint32]*series
	nextID uint32
	tiers  [2]tierStore
	dirty  bool
}

// SeriesInfo describes a stored series.
type SeriesInfo struct {
	ID     uint32 `json:"id"`
	Key    string `json:"key"`
	Series Series `json:"series"`
	FirstT int64  `json:"firstT"`
	LastT  int64  `json:"lastT"`
}

// Open creates a DB. With a Dir it loads the series index so rollups written
// before a restart stay queryable.
func Open(opts Options) (*DB, error) {
	opts.defaults()
	db := &DB{opts: opts, byKey: map[string]*series{}, byID: map[uint32]*series{}, nextID: 1}
	if opts.Dir == "" {
		db.tiers[0] = newMemTier(opts.MemTier1Rows)
		db.tiers[1] = newMemTier(opts.MemTier2Rows)
		return db, nil
	}
	t1, err := newDiskTier(filepath.Join(opts.Dir, "tier1"), 86400)
	if err != nil {
		return nil, err
	}
	t2, err := newDiskTier(filepath.Join(opts.Dir, "tier2"), 30*86400)
	if err != nil {
		return nil, err
	}
	db.tiers[0], db.tiers[1] = t1, t2
	if err := db.loadIndex(); err != nil {
		return nil, err
	}
	return db, nil
}

type indexEntry struct {
	ID     uint32 `json:"id"`
	Series Series `json:"series"`
	FirstT int64  `json:"firstT"`
	LastT  int64  `json:"lastT"`
}

func (db *DB) indexPath() string { return filepath.Join(db.opts.Dir, "series.json") }

func (db *DB) loadIndex() error {
	b, err := os.ReadFile(db.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries []indexEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return err
	}
	for _, e := range entries {
		s := &series{id: e.ID, meta: e.Series, firstT: e.FirstT, lastT: e.LastT}
		db.byKey[e.Series.Key()] = s
		db.byID[e.ID] = s
		if e.ID >= db.nextID {
			db.nextID = e.ID + 1
		}
	}
	return nil
}

func (db *DB) saveIndex() error {
	if db.opts.Dir == "" {
		return nil
	}
	db.mu.RLock()
	if !db.dirty {
		db.mu.RUnlock()
		return nil
	}
	entries := make([]indexEntry, 0, len(db.byID))
	for _, s := range db.byID {
		s.mu.Lock()
		entries = append(entries, indexEntry{ID: s.id, Series: s.meta, FirstT: s.firstT, LastT: s.lastT})
		s.mu.Unlock()
	}
	db.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	tmp := db.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, db.indexPath()); err != nil {
		return err
	}
	db.mu.Lock()
	db.dirty = false
	db.mu.Unlock()
	return nil
}

func (db *DB) getOrCreate(meta Series) (*series, error) {
	key := meta.Key()
	db.mu.RLock()
	s := db.byKey[key]
	db.mu.RUnlock()
	if s != nil {
		return s, nil
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if s = db.byKey[key]; s != nil {
		return s, nil
	}
	if len(db.byKey) >= db.opts.MaxSeries {
		return nil, ErrSeriesLimit
	}
	s = &series{id: db.nextID, meta: meta}
	db.nextID++
	db.byKey[key] = s
	db.byID[s.id] = s
	db.dirty = true
	return s, nil
}

// Append stores one sample.
func (db *DB) Append(smp Sample) error {
	s, err := db.getOrCreate(smp.Series)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastT != 0 && smp.T <= s.lastT {
		return ErrOutOfOrder
	}
	if smp.Units != "" || smp.Title != "" || smp.Family != "" {
		s.meta.Units, s.meta.Title, s.meta.Family, s.meta.ChartType = smp.Units, smp.Title, smp.Family, smp.ChartType
	}
	if len(s.chunks) == 0 || s.chunks[len(s.chunks)-1].full() {
		s.chunks = append(s.chunks, &chunk{})
	}
	s.chunks[len(s.chunks)-1].append(smp.T, smp.V, smp.Anomalous)
	if s.firstT == 0 {
		s.firstT = smp.T
	}
	s.lastT, s.lastV, s.lastA = smp.T, smp.V, smp.Anomalous
	for i, res := range []int64{Tier1Resolution, Tier2Resolution} {
		start := smp.T - smp.T%res
		if s.agg[i].Count > 0 && s.agg[i].Start != start {
			if err := db.tiers[i].write(s.id, s.agg[i]); err != nil {
				return err
			}
			s.agg[i] = Rollup{}
		}
		if s.agg[i].Count == 0 {
			s.agg[i].Start = start
		}
		s.agg[i].add(smp.V, smp.Anomalous)
	}
	return nil
}

// AppendBatch stores samples, skipping out-of-order ones. It returns the
// number stored and the first error that was not ErrOutOfOrder.
func (db *DB) AppendBatch(samples []Sample) (int, error) {
	n := 0
	var first error
	for _, s := range samples {
		err := db.Append(s)
		switch {
		case err == nil:
			n++
		case errors.Is(err, ErrOutOfOrder):
		case first == nil:
			first = err
		}
	}
	return n, first
}

// List returns every known series.
func (db *DB) List() []SeriesInfo {
	db.mu.RLock()
	all := make([]*series, 0, len(db.byID))
	for _, s := range db.byID {
		all = append(all, s)
	}
	db.mu.RUnlock()
	out := make([]SeriesInfo, 0, len(all))
	for _, s := range all {
		s.mu.Lock()
		out = append(out, SeriesInfo{ID: s.id, Key: s.meta.Key(), Series: s.meta, FirstT: s.firstT, LastT: s.lastT})
		s.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Last returns the newest sample of a series.
func (db *DB) Last(key string) (Point, bool) {
	db.mu.RLock()
	s := db.byKey[key]
	db.mu.RUnlock()
	if s == nil {
		return Point{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastT == 0 || len(s.chunks) == 0 {
		return Point{}, false
	}
	return Point{T: s.lastT, V: s.lastV, Anomalous: s.lastA}, true
}

// LastT is the newest timestamp across all series, or 0.
func (db *DB) LastT() int64 {
	var last int64
	for _, info := range db.List() {
		last = max(last, info.LastT)
	}
	return last
}

// Points returns tier-0 points of a series in [after, before].
func (db *DB) Points(key string, after, before int64) []Point {
	db.mu.RLock()
	s := db.byKey[key]
	db.mu.RUnlock()
	if s == nil {
		return nil
	}
	return s.points(after, before)
}

func (s *series) points(after, before int64) []Point {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Point
	for _, c := range s.chunks {
		if c.last < after || c.first > before {
			continue
		}
		c.forEach(func(t int64, v float64, a bool) bool {
			if t > before {
				return false
			}
			if t >= after {
				out = append(out, Point{T: t, V: v, Anomalous: a})
			}
			return true
		})
	}
	return out
}

// Rollups returns rollups of tier (1 or 2) for the given series keys,
// including the bucket still being aggregated.
func (db *DB) Rollups(tier int, keys []string, after, before int64) (map[string][]Rollup, error) {
	if tier != 1 && tier != 2 {
		return nil, errors.New("tsdb: tier must be 1 or 2")
	}
	ids := map[uint32]bool{}
	idKey := map[uint32]string{}
	var live []*series
	db.mu.RLock()
	for _, k := range keys {
		if s := db.byKey[k]; s != nil {
			ids[s.id] = true
			idKey[s.id] = k
			live = append(live, s)
		}
	}
	db.mu.RUnlock()
	out := map[string][]Rollup{}
	err := db.tiers[tier-1].read(ids, after, before, func(id uint32, r Rollup) {
		out[idKey[id]] = append(out[idKey[id]], r)
	})
	if err != nil {
		return nil, err
	}
	for _, s := range live {
		s.mu.Lock()
		cur := s.agg[tier-1]
		s.mu.Unlock()
		if cur.Count > 0 && cur.Start >= after && cur.Start <= before {
			k := idKey[s.id]
			out[k] = append(out[k], cur)
		}
	}
	for k := range out {
		rows := out[k]
		sort.Slice(rows, func(i, j int) bool { return rows[i].Start < rows[j].Start })
	}
	return out, nil
}

// SeriesPoints is a batch of tier-0 points for one series.
type SeriesPoints struct {
	Series Series  `json:"series"`
	Points []Point `json:"points"`
}

// Since returns tier-0 points newer than after, oldest first, stopping once
// roughly maxPoints have been collected. The returned cursor is the newest
// timestamp that is complete across every series in the batch.
func (db *DB) Since(after int64, maxPoints int) ([]SeriesPoints, int64) {
	db.mu.RLock()
	all := make([]*series, 0, len(db.byID))
	for _, s := range db.byID {
		all = append(all, s)
	}
	db.mu.RUnlock()
	newest := int64(0)
	for _, s := range all {
		s.mu.Lock()
		newest = max(newest, s.lastT)
		s.mu.Unlock()
	}
	if newest <= after {
		return nil, after
	}
	// Choose an upper bound so the batch stays near maxPoints.
	before := newest
	if maxPoints > 0 && len(all) > 0 {
		span := int64(maxPoints / len(all))
		if span < 1 {
			span = 1
		}
		oldest := newest
		for _, s := range all {
			s.mu.Lock()
			for _, c := range s.chunks {
				if c.last > after {
					oldest = min(oldest, max(c.first, after+1))
					break
				}
			}
			s.mu.Unlock()
		}
		if oldest+span-1 < newest {
			before = oldest + span - 1
		}
	}
	var out []SeriesPoints
	for _, s := range all {
		pts := s.points(after+1, before)
		if len(pts) == 0 {
			continue
		}
		s.mu.Lock()
		meta := s.meta
		s.mu.Unlock()
		out = append(out, SeriesPoints{Series: meta, Points: pts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Series.Key() < out[j].Series.Key() })
	return out, before
}

// Maintain evicts expired tier-0 chunks, drops series with no data left,
// flushes rollups, enforces retention and quota, and saves the index.
func (db *DB) Maintain(now time.Time) error {
	cut := now.Unix() - int64(db.opts.Tier0Retention/time.Second)
	idleCut := now.Unix() - int64(db.opts.Tier1Retention/time.Second)
	db.mu.Lock()
	for key, s := range db.byKey {
		s.mu.Lock()
		i := 0
		for i < len(s.chunks) && s.chunks[i].last < cut {
			i++
		}
		if i > 0 {
			s.chunks = append(s.chunks[:0:0], s.chunks[i:]...)
		}
		drop := len(s.chunks) == 0 && s.lastT != 0 && s.lastT < idleCut
		s.mu.Unlock()
		if drop {
			delete(db.byKey, key)
			delete(db.byID, s.id)
			db.dirty = true
		}
	}
	db.mu.Unlock()
	var errs []error
	quota1 := db.opts.DiskQuotaBytes * 8 / 10
	quota2 := db.opts.DiskQuotaBytes - quota1
	errs = append(errs, db.tiers[0].flush(), db.tiers[1].flush())
	errs = append(errs, db.tiers[0].enforce(now.Unix(), int64(db.opts.Tier1Retention/time.Second), quota1))
	errs = append(errs, db.tiers[1].enforce(now.Unix(), int64(db.opts.Tier2Retention/time.Second), quota2))
	errs = append(errs, db.saveIndex())
	return errors.Join(errs...)
}

// Run calls Maintain every interval until ctx ends.
func (db *DB) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := db.Maintain(now); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// Stats summarizes the store.
type Stats struct {
	Series      int   `json:"series"`
	MemoryBytes int64 `json:"memoryBytes"`
	DiskBytes   int64 `json:"diskBytes"`
	OldestT     int64 `json:"oldestT"`
	NewestT     int64 `json:"newestT"`
}

func (db *DB) Stats() Stats {
	db.mu.RLock()
	all := make([]*series, 0, len(db.byID))
	for _, s := range db.byID {
		all = append(all, s)
	}
	db.mu.RUnlock()
	st := Stats{Series: len(all)}
	for _, s := range all {
		s.mu.Lock()
		for _, c := range s.chunks {
			st.MemoryBytes += int64(c.sizeBytes())
		}
		st.MemoryBytes += 256
		if s.firstT != 0 && (st.OldestT == 0 || s.firstT < st.OldestT) {
			st.OldestT = s.firstT
		}
		st.NewestT = max(st.NewestT, s.lastT)
		s.mu.Unlock()
	}
	if db.opts.Dir == "" {
		st.MemoryBytes += db.tiers[0].sizeBytes() + db.tiers[1].sizeBytes()
	} else {
		st.DiskBytes = db.tiers[0].sizeBytes() + db.tiers[1].sizeBytes()
	}
	return st
}

// Retention returns the configured retention per tier.
func (db *DB) Retention() [3]time.Duration {
	return [3]time.Duration{db.opts.Tier0Retention, db.opts.Tier1Retention, db.opts.Tier2Retention}
}

// Close flushes pending rollups and the index.
func (db *DB) Close() error {
	db.mu.RLock()
	all := make([]*series, 0, len(db.byID))
	for _, s := range db.byID {
		all = append(all, s)
	}
	db.mu.RUnlock()
	var errs []error
	for _, s := range all {
		s.mu.Lock()
		for i := range s.agg {
			if s.agg[i].Count > 0 {
				errs = append(errs, db.tiers[i].write(s.id, s.agg[i]))
				s.agg[i] = Rollup{}
			}
		}
		s.mu.Unlock()
	}
	db.mu.Lock()
	db.dirty = true
	db.mu.Unlock()
	errs = append(errs, db.saveIndex(), db.tiers[0].close(), db.tiers[1].close())
	return errors.Join(errs...)
}
