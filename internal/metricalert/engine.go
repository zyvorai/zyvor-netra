// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricalert

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/notify"
	"github.com/zyvorai/netra/internal/tsdb"
)

// Status of one alert instance.
type Status string

const (
	StatusUndefined Status = "undefined"
	StatusClear     Status = "clear"
	StatusWarning   Status = "warning"
	StatusCritical  Status = "critical"
)

// Netdata-compatible status codes for $status, $WARNING and friends.
func (s Status) code() float64 {
	switch s {
	case StatusClear:
		return 1
	case StatusWarning:
		return 3
	case StatusCritical:
		return 4
	}
	return -1
}

func (s Status) raised() bool { return s == StatusWarning || s == StatusCritical }

func (s Status) rank() int {
	switch s {
	case StatusWarning:
		return 2
	case StatusCritical:
		return 3
	case StatusClear:
		return 1
	}
	return 0
}

// Alert is one rule instance (a rule on one node and chart or dimension).
type Alert struct {
	ID         string            `json:"id"`
	Rule       string            `json:"rule"`
	Node       string            `json:"node"`
	Context    string            `json:"context"`
	Chart      string            `json:"chart"`
	Dimension  string            `json:"dimension,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Status     Status            `json:"status"`
	Value      tsdb.NullFloat    `json:"value"`
	Units      string            `json:"units,omitempty"`
	Class      string            `json:"class,omitempty"`
	Info       string            `json:"info,omitempty"`
	Since      time.Time         `json:"since"`
	LastEval   time.Time         `json:"lastEval"`
	Silenced   bool              `json:"silenced,omitempty"`
	Acked      bool              `json:"acked,omitempty"`
	AckedBy    string            `json:"ackedBy,omitempty"`
	pending    Status
	pendingAt  time.Time
	lastNotify time.Time
	lastSeen   time.Time
}

// Transition is one status change, kept in a bounded history.
type Transition struct {
	Time     time.Time      `json:"time"`
	ID       string         `json:"id"`
	Rule     string         `json:"rule"`
	Node     string         `json:"node"`
	Chart    string         `json:"chart"`
	From     Status         `json:"from"`
	To       Status         `json:"to"`
	Value    tsdb.NullFloat `json:"value"`
	Units    string         `json:"units,omitempty"`
	Info     string         `json:"info,omitempty"`
	Silenced bool           `json:"silenced,omitempty"`
}

// Silence suppresses notifications for matching alerts until Until. Status
// is still tracked and shown.
type Silence struct {
	ID        string    `json:"id"`
	Rule      string    `json:"rule,omitempty"`  // glob
	Node      string    `json:"node,omitempty"`  // glob
	Chart     string    `json:"chart,omitempty"` // glob
	Until     time.Time `json:"until"`
	Comment   string    `json:"comment,omitempty"`
	CreatedBy string    `json:"createdBy,omitempty"`
	Created   time.Time `json:"created"`
}

func (s Silence) matches(a *Alert) bool {
	g := func(p, v string) bool { return p == "" || tsdb.MatchGlob(p, v) }
	return g(s.Rule, a.Rule) && g(s.Node, a.Node) && g(s.Chart, a.Chart)
}

// Options configures an Engine.
type Options struct {
	Rules   []Rule
	Sources func() []tsdb.Source
	// Publish delivers notifications; nil keeps alerts API-only.
	Publish func(notify.Event) bool
	Log     *slog.Logger
	// SilenceFile persists silences across restarts; empty keeps them in memory.
	SilenceFile string
	HistorySize int // default 1000
	MaxAlerts   int // instance cap, default 50000
}

// Engine evaluates rules on a schedule.
type Engine struct {
	opts     Options
	mu       sync.Mutex
	rules    []*compiled
	nextEval map[string]time.Time
	alerts   map[string]*Alert
	history  []Transition
	silences map[string]Silence
	evals    uint64
	dropped  uint64
}

// ErrNotFound is returned for an unknown alert or silence ID.
var ErrNotFound = errors.New("not found")

// New compiles opts.Rules. A rule that does not compile is an error.
func New(opts Options) (*Engine, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.HistorySize <= 0 {
		opts.HistorySize = 1000
	}
	if opts.MaxAlerts <= 0 {
		opts.MaxAlerts = 50000
	}
	e := &Engine{opts: opts, nextEval: map[string]time.Time{}, alerts: map[string]*Alert{}, silences: map[string]Silence{}}
	seen := map[string]bool{}
	for _, r := range opts.Rules {
		if seen[r.Name] {
			return nil, fmt.Errorf("duplicate rule %q", r.Name)
		}
		seen[r.Name] = true
		c, err := compile(r)
		if err != nil {
			return nil, err
		}
		e.rules = append(e.rules, c)
	}
	e.loadSilences()
	return e, nil
}

// Run evaluates due rules every second until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.Evaluate(now)
		}
	}
}

func alertID(rule, node, chart, dim string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + node + "\x00" + chart + "\x00" + dim))
	return hex.EncodeToString(h[:8])
}

type instance struct {
	chart, dim string
	labels     map[string]string
	vals       []float64
	dimVals    map[string]float64
	anom       int
	total      int
}

// lookup reduces one series over [after, before]: tier 0 when the window is
// inside its retention, 1-minute rollups otherwise.
func lookup(db *tsdb.DB, key, fn string, after, before int64, now time.Time) (v float64, anom, total int) {
	if after >= now.Unix()-int64(db.Retention()[0]/time.Second) {
		pts := db.Points(key, after, before)
		if len(pts) == 0 {
			return math.NaN(), 0, 0
		}
		vals := make([]float64, 0, len(pts))
		for _, p := range pts {
			vals = append(vals, p.V)
			if p.Anomalous {
				anom++
			}
		}
		return reduce(fn, vals), anom, len(pts)
	}
	rs, err := db.Rollups(1, []string{key}, after, before)
	if err != nil || len(rs[key]) == 0 {
		return math.NaN(), 0, 0
	}
	var sum float64
	var cnt int
	mn, mx := math.Inf(1), math.Inf(-1)
	var last float64
	for _, r := range rs[key] {
		sum += r.Sum
		cnt += int(r.Count)
		mn, mx = math.Min(mn, r.Min), math.Max(mx, r.Max)
		last = r.Avg()
		anom += int(r.Anomalous)
	}
	switch fn {
	case "sum":
		v = sum
	case "min":
		v = mn
	case "max", "p90", "p95", "p99":
		v = mx
	case "last":
		v = last
	default:
		v = sum / float64(max(cnt, 1))
	}
	return v, anom, cnt
}

func reduce(fn string, vals []float64) float64 {
	switch fn {
	case "sum":
		var s float64
		for _, v := range vals {
			s += v
		}
		return s
	case "min":
		m := math.Inf(1)
		for _, v := range vals {
			m = math.Min(m, v)
		}
		return m
	case "max":
		m := math.Inf(-1)
		for _, v := range vals {
			m = math.Max(m, v)
		}
		return m
	case "last":
		return vals[len(vals)-1]
	case "p50":
		return tsdb.Percentile(vals, 50)
	case "p90":
		return tsdb.Percentile(vals, 90)
	case "p95":
		return tsdb.Percentile(vals, 95)
	case "p99":
		return tsdb.Percentile(vals, 99)
	}
	var s float64
	for _, v := range vals {
		s += v
	}
	return s / float64(len(vals))
}

func labelsMatch(want, have map[string]string) bool {
	for k, v := range want {
		if !tsdb.MatchGlob(v, have[k]) {
			return false
		}
	}
	return true
}

func aggregate(how string, vals []float64) float64 {
	if len(vals) == 0 {
		return math.NaN()
	}
	return reduce(how, vals)
}

// instances evaluates the rule's lookup on one node. It also returns the
// node's CPU count (NaN if unknown) and the aggregate to apply.
func (c *compiled) instances(db *tsdb.DB, now time.Time) (map[string]*instance, float64, string) {
	before := now.Unix()
	after := before - int64(c.window/time.Second)
	out := map[string]*instance{}
	ncpu := 0
	units := ""
	for _, info := range db.List() {
		s := info.Series
		if s.Context == "cpu.cpu" && s.Dimension == "user" {
			ncpu++
		}
		if s.Context != c.Context || !tsdb.MatchAny(c.charts, s.Chart) || !tsdb.MatchAny(c.dims, s.Dimension) || !labelsMatch(c.Labels, s.Labels) {
			continue
		}
		if info.LastT != 0 && info.LastT < after {
			continue
		}
		v, anom, total := lookup(db, info.Key, c.fn, after, before, now)
		if total == 0 {
			continue
		}
		if units == "" {
			units = s.Units
		}
		var key, chart, dim string
		switch c.Per {
		case "dimension":
			key, chart, dim = s.Chart+"/"+s.Dimension, s.Chart, s.Dimension
		case "node":
			key, chart = c.Context, c.Context
		default:
			key, chart = s.Chart, s.Chart
		}
		in := out[key]
		if in == nil {
			in = &instance{chart: chart, dim: dim, dimVals: map[string]float64{}}
			if c.Per != "node" {
				in.labels = s.Labels
			}
			out[key] = in
		}
		in.vals = append(in.vals, v)
		in.dimVals[s.Dimension] += v
		in.anom += anom
		in.total += total
	}
	agg := c.Aggregate
	if agg == "" {
		agg = "sum"
		if units == "%" || strings.HasPrefix(units, "percent") {
			agg = "avg"
		}
	}
	n := math.NaN()
	if ncpu > 0 {
		n = float64(ncpu)
	}
	return out, n, agg
}

// Evaluate runs every rule that is due at now.
func (e *Engine) Evaluate(now time.Time) {
	var sources []tsdb.Source
	if e.opts.Sources != nil {
		sources = e.opts.Sources()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var events []notify.Event
	for _, c := range e.rules {
		if now.Before(e.nextEval[c.Name]) {
			continue
		}
		e.nextEval[c.Name] = now.Add(c.every)
		e.evals++
		seen := map[string]bool{}
		for _, src := range sources {
			if src.DB == nil {
				continue
			}
			ins, ncpu, agg := c.instances(src.DB, now)
			for _, in := range ins {
				id := alertID(c.Name, src.Node, in.chart, in.dim)
				seen[id] = true
				val := aggregate(agg, in.vals)
				anomRate := math.NaN()
				if in.total > 0 {
					anomRate = 100 * float64(in.anom) / float64(in.total)
				}
				if c.fn == "anomaly-rate" {
					val = anomRate
				}
				a := e.alerts[id]
				if a == nil {
					if len(e.alerts) >= e.opts.MaxAlerts {
						e.dropped++
						continue
					}
					a = &Alert{ID: id, Rule: c.Name, Node: src.Node, Context: c.Context, Chart: in.chart, Dimension: in.dim, Labels: in.labels,
						Status: StatusUndefined, Units: c.Units, Class: c.Class, Info: c.Info, Since: now}
					e.alerts[id] = a
				}
				a.lastSeen = now
				if ev, ok := e.step(c, a, val, anomRate, ncpu, in.dimVals, now); ok {
					events = append(events, ev)
				}
			}
		}
		// Instances that produced no data this round go undefined.
		for id, a := range e.alerts {
			if a.Rule != c.Name || seen[id] {
				continue
			}
			if ev, ok := e.step(c, a, math.NaN(), math.NaN(), math.NaN(), nil, now); ok {
				events = append(events, ev)
			}
			if !a.Status.raised() && now.Sub(a.lastSeen) > time.Hour {
				delete(e.alerts, id)
			}
		}
	}
	e.expireSilences(now)
	publish := e.opts.Publish
	if publish != nil {
		for _, ev := range events {
			if !publish(ev) {
				e.opts.Log.Warn("metric alert notification dropped (queue full)", "rule", ev.Kind, "node", ev.Node)
			}
		}
	}
}

// step computes the candidate status for a, applies the delays and records
// a transition. It returns a notification when one should be sent.
func (e *Engine) step(c *compiled, a *Alert, raw, anomRate, ncpu float64, dims map[string]float64, now time.Time) (notify.Event, bool) {
	val := raw
	vars := func(name string) float64 {
		switch name {
		case "this":
			return val
		case "status":
			return a.Status.code()
		case "UNDEFINED":
			return -1
		case "CLEAR":
			return 1
		case "WARNING":
			return 3
		case "CRITICAL":
			return 4
		case "now":
			return float64(now.Unix())
		case "anomaly_rate":
			return anomRate
		case "ncpu":
			return ncpu
		}
		if v, ok := c.Vars[name]; ok {
			return v
		}
		if v, ok := dims[name]; ok {
			return v
		}
		return math.NaN()
	}
	if c.calc != nil {
		val = c.calc.Eval(vars)
	}
	a.Value = tsdb.NullFloat(val)
	a.LastEval = now
	cand := StatusUndefined
	if !math.IsNaN(val) {
		cand = StatusClear
		if truth(c.warn.Eval(vars)) {
			cand = StatusWarning
		}
		if truth(c.crit.Eval(vars)) {
			cand = StatusCritical
		}
	}
	a.Silenced = e.silenced(a)
	if cand == a.Status {
		a.pending = ""
		if a.Status.raised() && c.repeat > 0 && !a.Acked && !a.Silenced && now.Sub(a.lastNotify) >= c.repeat {
			a.lastNotify = now
			return e.event(a, now), true
		}
		return notify.Event{}, false
	}
	if a.pending != cand {
		a.pending, a.pendingAt = cand, now
	}
	wait := c.delayDown
	if cand.rank() > a.Status.rank() {
		wait = c.delayUp
	}
	// Leaving undefined for a first reading needs no delay unless it raises.
	if a.Status == StatusUndefined && !cand.raised() {
		wait = 0
	}
	if now.Sub(a.pendingAt) < wait {
		return notify.Event{}, false
	}
	from := a.Status
	a.Status, a.Since, a.pending = cand, now, ""
	a.Acked, a.AckedBy = false, ""
	e.history = append(e.history, Transition{Time: now, ID: a.ID, Rule: a.Rule, Node: a.Node, Chart: a.Chart, From: from, To: cand, Value: a.Value, Units: a.Units, Info: a.Info, Silenced: a.Silenced})
	if over := len(e.history) - e.opts.HistorySize; over > 0 {
		e.history = append(e.history[:0:0], e.history[over:]...)
	}
	notifyIt := cand.raised() || (from.raised() && cand == StatusClear)
	if !notifyIt || a.Silenced {
		return notify.Event{}, false
	}
	a.lastNotify = now
	return e.event(a, now), true
}

func (e *Engine) event(a *Alert, now time.Time) notify.Event {
	sev := "info"
	switch a.Status {
	case StatusWarning:
		sev = "warning"
	case StatusCritical:
		sev = "critical"
	}
	subject := a.Chart
	if a.Dimension != "" {
		subject += "/" + a.Dimension
	}
	msg := fmt.Sprintf("%s is %s on %s (%s): %s %s", a.Rule, a.Status, a.Node, subject, formatValue(float64(a.Value)), a.Units)
	if a.Info != "" {
		msg += " — " + a.Info
	}
	return notify.Event{Source: "metricalert", Kind: a.Rule, Severity: sev, Subject: subject, Message: strings.TrimSpace(msg), Value: float64(a.Value), Node: a.Node, Timestamp: now}
}

func formatValue(v float64) string {
	if math.IsNaN(v) {
		return "n/a"
	}
	if math.Abs(v) >= 100 || v == math.Trunc(v) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.2f", v)
}

func (e *Engine) silenced(a *Alert) bool {
	for _, s := range e.silences {
		if s.matches(a) {
			return true
		}
	}
	return false
}

func (e *Engine) expireSilences(now time.Time) {
	changed := false
	for id, s := range e.silences {
		if !now.Before(s.Until) {
			delete(e.silences, id)
			changed = true
		}
	}
	if changed {
		e.saveSilences()
	}
}

// Snapshot is the API view.
type Snapshot struct {
	Active   []Alert      `json:"active"`
	History  []Transition `json:"history"`
	Rules    []Rule       `json:"rules"`
	Silences []Silence    `json:"silences"`
	Stats    Stats        `json:"stats"`
}

// Stats summarizes the engine.
type Stats struct {
	Rules     int    `json:"rules"`
	Instances int    `json:"instances"`
	Warning   int    `json:"warning"`
	Critical  int    `json:"critical"`
	Evals     uint64 `json:"evaluations"`
	Dropped   uint64 `json:"droppedInstances"`
}

// Snapshot returns raised alerts (all instances with all=true), the most
// recent history entries first, rules and silences.
func (e *Engine) Snapshot(all bool, historyLimit int) Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := Snapshot{Active: []Alert{}, History: []Transition{}, Silences: []Silence{}, Rules: make([]Rule, 0, len(e.rules))}
	for _, a := range e.alerts {
		switch a.Status {
		case StatusWarning:
			out.Stats.Warning++
		case StatusCritical:
			out.Stats.Critical++
		}
		if all || a.Status.raised() {
			cp := *a
			out.Active = append(out.Active, cp)
		}
	}
	sort.Slice(out.Active, func(i, j int) bool {
		a, b := out.Active[i], out.Active[j]
		if a.Status.rank() != b.Status.rank() {
			return a.Status.rank() > b.Status.rank()
		}
		if !a.Since.Equal(b.Since) {
			return a.Since.After(b.Since)
		}
		return a.ID < b.ID
	})
	if historyLimit <= 0 || historyLimit > len(e.history) {
		historyLimit = len(e.history)
	}
	for i := len(e.history) - 1; i >= len(e.history)-historyLimit; i-- {
		out.History = append(out.History, e.history[i])
	}
	for _, c := range e.rules {
		out.Rules = append(out.Rules, c.Rule)
	}
	for _, s := range e.silences {
		out.Silences = append(out.Silences, s)
	}
	sort.Slice(out.Silences, func(i, j int) bool { return out.Silences[i].Until.Before(out.Silences[j].Until) })
	out.Stats.Rules = len(e.rules)
	out.Stats.Instances = len(e.alerts)
	out.Stats.Evals = e.evals
	out.Stats.Dropped = e.dropped
	return out
}

// Active returns raised alerts, most severe first.
func (e *Engine) Active() []Alert { return e.Snapshot(false, 1).Active }

// Ack acknowledges an alert until its next status change; repeats stop.
func (e *Engine) Ack(id, by string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.alerts[id]
	if a == nil || !a.Status.raised() {
		return ErrNotFound
	}
	a.Acked, a.AckedBy = true, by
	return nil
}

// AddSilence stores s, assigning an ID. Until must be in the future and at
// most 30 days away; at least one matcher is required.
func (e *Engine) AddSilence(s Silence, now time.Time) (Silence, error) {
	if s.Rule == "" && s.Node == "" && s.Chart == "" {
		return Silence{}, errors.New("a silence needs a rule, node or chart matcher")
	}
	if !s.Until.After(now) || s.Until.Sub(now) > 30*24*time.Hour {
		return Silence{}, errors.New("until must be within the next 30 days")
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	s.ID, s.Created = hex.EncodeToString(b[:]), now
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.silences) >= 1000 {
		return Silence{}, errors.New("too many silences")
	}
	e.silences[s.ID] = s
	for _, a := range e.alerts {
		a.Silenced = e.silenced(a)
	}
	e.saveSilences()
	return s, nil
}

// DeleteSilence removes a silence.
func (e *Engine) DeleteSilence(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.silences[id]; !ok {
		return ErrNotFound
	}
	delete(e.silences, id)
	for _, a := range e.alerts {
		a.Silenced = e.silenced(a)
	}
	e.saveSilences()
	return nil
}

func (e *Engine) loadSilences() {
	if e.opts.SilenceFile == "" {
		return
	}
	data, err := os.ReadFile(e.opts.SilenceFile)
	if err != nil {
		return
	}
	var ss []Silence
	if err := json.Unmarshal(data, &ss); err != nil {
		e.opts.Log.Warn("ignoring unreadable metric alert silences", "file", e.opts.SilenceFile, "error", err)
		return
	}
	for _, s := range ss {
		if s.ID != "" {
			e.silences[s.ID] = s
		}
	}
}

func (e *Engine) saveSilences() {
	if e.opts.SilenceFile == "" {
		return
	}
	ss := make([]Silence, 0, len(e.silences))
	for _, s := range e.silences {
		ss = append(ss, s)
	}
	data, _ := json.Marshal(ss)
	tmp := e.opts.SilenceFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		err = os.Rename(tmp, e.opts.SilenceFile)
		if err != nil {
			e.opts.Log.Warn("save metric alert silences", "error", err)
		}
	}
}
