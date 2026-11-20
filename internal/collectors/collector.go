// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package collectors gathers per-second host, network, cgroup, process
// group and application metrics into tsdb samples. Every collector is
// read-only: it parses /proc, /sys, cgroupfs or an application status
// endpoint and never writes to the system it observes. The process-group
// collector reads /proc/<pid>/stat, statm and io only; it never opens
// cmdline or environ.
package collectors

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// Info describes a collector.
type Info struct {
	Name   string        `json:"name"`
	Family string        `json:"family"`
	Every  time.Duration `json:"every"` // default 1s
}

// Collector produces samples on each tick.
type Collector interface {
	Info() Info
	Collect(now time.Time, e *Emitter) error
}

// Chart groups the dimensions emitted together.
type Chart struct {
	Context string
	ID      string
	Family  string
	Units   string
	Title   string
	Type    string // line, area, stacked
	Labels  map[string]string
}

// Emitter collects samples for one collector run and keeps the previous
// raw value of every incremental dimension across runs.
type Emitter struct {
	now   time.Time
	out   []tsdb.Sample
	state *rateState
}

type prevVal struct {
	at   time.Time
	v    float64
	run  uint64
	seen bool
}

type rateState struct {
	run  uint64
	prev map[string]*prevVal
}

func newRateState() *rateState { return &rateState{prev: map[string]*prevVal{}} }

// NewEmitter returns a standalone emitter, used by tests and by callers that
// drive a collector without a Scheduler. Reuse the same emitter across runs
// so incremental dimensions can compute rates.
func NewEmitter() *Emitter { return &Emitter{state: newRateState()} }

// Begin starts a new run at now and clears the previous run's samples.
func (e *Emitter) Begin(now time.Time) {
	e.now = now
	e.out = e.out[:0]
	e.state.run++
}

// Samples returns the samples emitted since Begin.
func (e *Emitter) Samples() []tsdb.Sample { return e.out }

// End forgets incremental dimensions not seen for 120 runs.
func (e *Emitter) End() {
	for k, p := range e.state.prev {
		if e.state.run-p.run > 120 {
			delete(e.state.prev, k)
		}
	}
}

func (c Chart) series(dim string) tsdb.Series {
	id := c.ID
	if id == "" {
		id = c.Context
	}
	return tsdb.Series{Context: c.Context, Chart: id, Dimension: dim, Family: c.Family, Units: c.Units, Title: c.Title, ChartType: c.Type, Labels: c.Labels}
}

// Gauge emits an absolute value. NaN and infinities are dropped.
func (e *Emitter) Gauge(c Chart, dim string, v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	e.out = append(e.out, tsdb.Sample{Series: c.series(dim), T: e.now.Unix(), V: v})
}

// Incremental emits the per-second rate of a monotonically increasing
// counter multiplied by mult. The first observation and counter resets emit
// nothing.
func (e *Emitter) Incremental(c Chart, dim string, raw float64, mult float64) {
	s := c.series(dim)
	key := s.Key()
	p := e.state.prev[key]
	if p == nil {
		p = &prevVal{}
		e.state.prev[key] = p
	}
	if p.seen && raw >= p.v {
		dt := e.now.Sub(p.at).Seconds()
		if dt > 0 && !math.IsInf(raw, 0) {
			e.out = append(e.out, tsdb.Sample{Series: s, T: e.now.Unix(), V: (raw - p.v) / dt * mult})
		}
	}
	p.at, p.v, p.run, p.seen = e.now, raw, e.state.run, true
}

// fsys resolves host paths under a root so tests can point at fixtures and
// containers can point at a host mount.
type fsys struct {
	proc string // e.g. /proc
	sys  string // e.g. /sys
}

func (f fsys) procPath(parts ...string) string {
	return filepath.Join(append([]string{f.proc}, parts...)...)
}
func (f fsys) sysPath(parts ...string) string {
	return filepath.Join(append([]string{f.sys}, parts...)...)
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readFloat(path string) (float64, bool) {
	s, err := readTrim(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

func pf(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		u, uerr := strconv.ParseUint(s, 10, 64)
		if uerr != nil {
			return 0
		}
		return float64(u)
	}
	return v
}

func phex(s string) float64 {
	v, _ := strconv.ParseUint(s, 16, 64)
	return float64(v)
}

// keyValueFile parses "key value [unit]" lines such as /proc/meminfo and
// /proc/vmstat, stripping a trailing colon from keys.
func keyValueFile(path string) (map[string]float64, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(lines))
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		out[strings.TrimSuffix(f[0], ":")] = pf(f[1])
	}
	return out, nil
}

// headerPairs parses the paired header/value line format of /proc/net/snmp
// and /proc/net/netstat into section -> field -> value.
func headerPairs(path string) (map[string]map[string]float64, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]float64{}
	for i := 0; i+1 < len(lines); i += 2 {
		h := strings.Fields(lines[i])
		v := strings.Fields(lines[i+1])
		if len(h) == 0 || len(h) != len(v) || h[0] != v[0] {
			continue
		}
		sec := strings.TrimSuffix(h[0], ":")
		m := out[sec]
		if m == nil {
			m = map[string]float64{}
			out[sec] = m
		}
		for j := 1; j < len(h); j++ {
			m[h[j]] = pf(v[j])
		}
	}
	return out, nil
}
