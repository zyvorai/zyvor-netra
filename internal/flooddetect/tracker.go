// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package flooddetect

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// MaxSourcesPerSnapshot bounds the per-source counters kept per node.
	MaxSourcesPerSnapshot = 5000
	// MaxSourceFindings bounds source findings returned.
	MaxSourceFindings = 100
	// MaxNodes bounds how many nodes the tracker remembers.
	MaxNodes    = 2000
	minInterval = time.Second
	maxInterval = 15 * time.Minute
	// StaleAfter is how long a node's last rates stay reportable.
	StaleAfter = 5 * time.Minute
)

// SourceFloors are the per-source rates (events per second) below which a
// source is not reported, by shield class.
var SourceFloors = map[string]float64{"syn": 200, "udp": 2000, "icmp": 500, "other": 2000}

type counter struct{ attempts, denied uint64 }

type snapshot struct {
	at  time.Time
	src map[string]counter // class + "\x00" + address
}

type nodeRates struct {
	at    time.Time
	rates []SourceRate
}

// SourceRate is one source's rate of new-connection attempts (SYN class) or
// shield-denied packets (other classes) between two observations.
type SourceRate struct {
	Node     string  `json:"node"`
	Class    string  `json:"class"`
	Address  string  `json:"address"`
	PerSec   float64 `json:"perSecond"`
	Share    float64 `json:"shareOfClass"` // of all sources' rate for this node and class
	Interval float64 `json:"intervalSeconds"`
}

// SourceFinding is a source above its class floor.
type SourceFinding struct {
	SourceRate
	Floor      float64     `json:"floorPerSecond"`
	Severity   string      `json:"severity"`
	Message    string      `json:"message"`
	Suggestion *Suggestion `json:"suggestion,omitempty"`
	// NoSuggestion explains why no deny is suggested.
	NoSuggestion string `json:"noSuggestion,omitempty"`
}

// Tracker turns consecutive shield-source snapshots into rates. It is fed by
// a poller and read by the API. All methods are safe for concurrent use. A
// restart discards history: rates are "warming" until two observations
// arrive.
type Tracker struct {
	mu    sync.Mutex
	prev  map[string]snapshot
	rates map[string]nodeRates
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{prev: map[string]snapshot{}, rates: map[string]nodeRates{}}
}

func key(class, address string) string { return class + "\x00" + address }

// Observe records one node's per-source counters at time at.
func (t *Tracker) Observe(node string, at time.Time, sources []models.ShieldSourceStat) {
	if t == nil || node == "" {
		return
	}
	srcs := sources
	if len(srcs) > MaxSourcesPerSnapshot {
		srcs = append([]models.ShieldSourceStat(nil), srcs...)
		sort.Slice(srcs, func(i, j int) bool { return srcs[i].Attempts+srcs[i].Denied > srcs[j].Attempts+srcs[j].Denied })
		srcs = srcs[:MaxSourcesPerSnapshot]
	}
	cur := snapshot{at: at, src: make(map[string]counter, len(srcs))}
	for _, s := range srcs {
		if s.Address == "" || len(s.Address) > 64 {
			continue
		}
		class := strings.ToLower(s.Class)
		if _, ok := SourceFloors[class]; !ok {
			class = "other"
		}
		k := key(class, s.Address)
		c := cur.src[k]
		c.attempts += s.Attempts
		c.denied += s.Denied
		cur.src[k] = c
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, had := t.prev[node]
	if !had && len(t.prev) >= MaxNodes {
		return
	}
	t.prev[node] = cur
	if !had {
		return
	}
	dt := at.Sub(p.at)
	if dt < minInterval || dt > maxInterval {
		return
	}
	sec := dt.Seconds()
	var rates []SourceRate
	totals := map[string]float64{}
	for k, c := range cur.src {
		o, ok := p.src[k]
		if !ok || c.attempts < o.attempts || c.denied < o.denied {
			continue // new source or a counter reset: no rate this interval
		}
		class, addr, _ := strings.Cut(k, "\x00")
		d := c.denied - o.denied
		if class == "syn" {
			d = c.attempts - o.attempts
		}
		r := float64(d) / sec
		if r <= 0 || math.IsInf(r, 0) || math.IsNaN(r) {
			continue
		}
		totals[class] += r
		rates = append(rates, SourceRate{Node: node, Class: class, Address: addr, PerSec: round2(r), Interval: round2(sec)})
	}
	for i := range rates {
		if tot := totals[rates[i].Class]; tot > 0 {
			rates[i].Share = round2(rates[i].PerSec / tot)
		}
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].PerSec > rates[j].PerSec })
	if len(rates) > MaxSourceFindings*2 {
		rates = rates[:MaxSourceFindings*2]
	}
	t.rates[node] = nodeRates{at: at, rates: rates}
}

// Warming reports whether no node has produced a rate yet.
func (t *Tracker) Warming(now time.Time) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range t.rates {
		if now.Sub(r.at) <= StaleAfter {
			return false
		}
	}
	return true
}

// Findings returns sources above their class floor, worst first. Rates older
// than StaleAfter are ignored. Each finding carries a deny suggestion when
// the source is a public address.
func (t *Tracker) Findings(now time.Time) []SourceFinding {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	var all []SourceRate
	for _, r := range t.rates {
		if now.Sub(r.at) <= StaleAfter {
			all = append(all, r.rates...)
		}
	}
	t.mu.Unlock()
	var out []SourceFinding
	for _, r := range all {
		floor := SourceFloors[r.Class]
		if r.PerSec < floor {
			continue
		}
		x := r.PerSec / floor
		sev := SeverityWarning
		switch {
		case x >= 10:
			sev = SeverityCritical
		case x >= 3:
			sev = SeverityHigh
		}
		f := SourceFinding{SourceRate: r, Floor: floor, Severity: sev,
			Message: fmt.Sprintf("%s sends %.0f/s (%s class, %.0f%% of this node's %s rate)", r.Address, r.PerSec, r.Class, r.Share*100, r.Class)}
		if sg, why := Suggest(r.Address, r.Class); sg != nil {
			f.Suggestion = sg
		} else {
			f.NoSuggestion = why
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank(out[i].Severity) != sevRank(out[j].Severity) {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		return out[i].PerSec > out[j].PerSec
	})
	if len(out) > MaxSourceFindings {
		out = out[:MaxSourceFindings]
	}
	return out
}

// Run feeds the tracker from fetch every interval until ctx ends. Stale
// agents are skipped. It reads agent reports only.
func (t *Tracker) Run(ctx context.Context, interval time.Duration, fetch func() []models.AgentStatus) {
	if t == nil || fetch == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	obs := func() {
		now := time.Now()
		for _, a := range fetch() {
			if !a.Stale {
				t.Observe(a.Node, now, a.ShieldSources)
			}
		}
	}
	obs()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			obs()
		}
	}
}
