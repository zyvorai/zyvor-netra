// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package scandetect flags port scans, fan-out, and lateral-movement
// patterns from Netra's existing per-workload destination-attempt counters.
//
// Observe-only. No new eBPF program. Bounded memory via time-windowed
// sketches and LRU.
package scandetect

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Event is one observed outbound connection attempt (SYN or sendmsg).
type Event struct {
	Timestamp time.Time

	// Source attribution from the eBPF datapath.
	Namespace string
	Pod       string
	Workload  string
	Node      string
	Comm      string

	// Destination (post-NAT if sourced from TC; local socket if from sockops).
	DstIP   string
	DstPort uint16

	// Optional verdict if the datapath provided one.
	SynOnly bool // saw SYN, no ACK
	Reset   bool // RST observed
}

// Config controls thresholds. Every knob is exposed via Helm.
type Config struct {
	Window             time.Duration // analysis window, e.g. 60s
	MaxDestIPs         int           // unique dest IPs before flagging fan-out
	MaxDestPorts       int           // unique dest ports before flagging port-scan
	MinAttempts        uint64        // minimum attempts before scoring
	SynRatio           float64       // SYN-only / total ratio threshold
	ResetRatio         float64       // RST / total ratio threshold
	MaxWorkloads       int           // LRU cap
	MaxDestPerWorkload int           // per-workload dst set cap
	FindingsTTL        time.Duration
	MaxFindings        int
}

// DefaultConfig returns conservative production defaults.
func DefaultConfig() Config {
	return Config{
		Window:             60 * time.Second,
		MaxDestIPs:         50,
		MaxDestPorts:       50,
		MinAttempts:        20,
		SynRatio:           0.8,
		ResetRatio:         0.5,
		MaxWorkloads:       10000,
		MaxDestPerWorkload: 500,
		FindingsTTL:        10 * time.Minute,
		MaxFindings:        2048,
	}
}

// Severity mirrors Netra's existing vocabulary.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// FindingType classifies a detection.
type FindingType string

const (
	FindingPortScan FindingType = "port_scan"
	FindingFanOut   FindingType = "fan_out"
	FindingLateral  FindingType = "lateral_movement"
	FindingSYNFlood FindingType = "syn_flood"
)

// Finding is a single detection result.
type Finding struct {
	ID       string      `json:"id"`
	Type     FindingType `json:"type"`
	Severity Severity    `json:"severity"`
	Score    float64     `json:"score"`
	Signals  []string    `json:"signals"`

	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Node      string `json:"node,omitempty"`
	Comm      string `json:"comm,omitempty"`

	UniqueDstIPs   int    `json:"uniqueDstIps"`
	UniqueDstPorts int    `json:"uniqueDstPorts"`
	Attempts       uint64 `json:"attempts"`
	SYNOnly        uint64 `json:"synOnly"`
	Resets         uint64 `json:"resets"`

	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`

	ExampleDsts []string `json:"exampleDsts,omitempty"`
}

type workloadKey struct {
	namespace string
	pod       string
}

type state struct {
	key       workloadKey
	workload  string
	node      string
	comm      string
	firstSeen time.Time
	lastSeen  time.Time

	attempts uint64
	synOnly  uint64
	resets   uint64

	dstIPs   map[string]struct{}
	dstPorts map[uint16]struct{}

	examples []string
}

// Snapshot is a metric payload.
type Snapshot struct {
	AttemptsSeen     uint64                 `json:"attemptsSeen"`
	WorkloadsTracked uint64                 `json:"workloadsTracked"`
	ActiveFindings   uint64                 `json:"activeFindings"`
	FindingsTotal    map[FindingType]uint64 `json:"findingsTotal"`
}

type findingKey struct {
	ftype FindingType
	ns    string
	pod   string
}

// Detector is the engine. Safe for concurrent use.
type Detector struct {
	mu       sync.Mutex
	cfg      Config
	states   map[workloadKey]*state
	order    []workloadKey
	pos      int
	findings map[findingKey]*Finding
}

// New creates a Detector.
func New(cfg Config) *Detector {
	cfg = normalize(cfg)
	return &Detector{
		cfg:      cfg,
		states:   make(map[workloadKey]*state),
		findings: make(map[findingKey]*Finding),
	}
}

// Config returns a copy of the current config.
func (d *Detector) Config() Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg
}

// SetConfig replaces thresholds. Existing state is preserved.
func (d *Detector) SetConfig(cfg Config) {
	cfg = normalize(cfg)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg = cfg
}

// Observe ingests one connection-attempt event.
func (d *Detector) Observe(e Event) {
	if e.DstIP == "" || e.Timestamp.IsZero() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	key := workloadKey{namespace: e.Namespace, pod: e.Pod}
	st, existed := d.states[key]
	if !existed {
		st = &state{
			key:      key,
			dstIPs:   make(map[string]struct{}),
			dstPorts: make(map[uint16]struct{}),
		}
		d.states[key] = st
		d.order = append(d.order, key)
	}
	st.workload = e.Workload
	st.node = e.Node
	st.comm = e.Comm

	// Window reset when the gap exceeds Window.
	if !st.lastSeen.IsZero() && e.Timestamp.Sub(st.lastSeen) > d.cfg.Window {
		clearState(st)
	}
	if st.firstSeen.IsZero() {
		st.firstSeen = e.Timestamp
	}
	st.lastSeen = e.Timestamp

	st.attempts++
	if e.SynOnly {
		st.synOnly++
	}
	if e.Reset {
		st.resets++
	}

	if len(st.dstIPs) < d.cfg.MaxDestPerWorkload {
		st.dstIPs[e.DstIP] = struct{}{}
	}
	if len(st.dstPorts) < d.cfg.MaxDestPerWorkload {
		st.dstPorts[e.DstPort] = struct{}{}
	}
	if len(st.examples) < 5 {
		dst := e.DstIP + ":" + strconv.Itoa(int(e.DstPort))
		if !slices.Contains(st.examples, dst) {
			st.examples = append(st.examples, dst)
		}
	}

	d.evaluate(st)
	d.evictIfNeeded()
}

// Findings returns active findings (TTL-filtered), deep-copied.
func (d *Detector) Findings() []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-d.cfg.FindingsTTL)
	out := make([]Finding, 0, len(d.findings))
	for _, f := range d.findings {
		if f.LastSeen.Before(cutoff) {
			continue
		}
		cp := *f
		cp.Signals = append([]string(nil), f.Signals...)
		cp.ExampleDsts = append([]string(nil), f.ExampleDsts...)
		out = append(out, cp)
	}
	return out
}

// Snapshot returns counters for Prometheus / API.
func (d *Detector) Snapshot() Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	counts := map[FindingType]uint64{}
	for _, f := range d.findings {
		counts[f.Type]++
	}
	var attempts uint64
	for _, s := range d.states {
		attempts += s.attempts
	}
	return Snapshot{
		AttemptsSeen:     attempts,
		WorkloadsTracked: uint64(len(d.states)),
		ActiveFindings:   uint64(len(d.findings)),
		FindingsTotal:    counts,
	}
}

// ---------- evaluation ----------

func (d *Detector) evaluate(st *state) {
	if st.attempts < d.cfg.MinAttempts {
		return
	}
	uIPs := len(st.dstIPs)
	uPorts := len(st.dstPorts)
	synRatio := float64(st.synOnly) / float64(st.attempts)
	rstRatio := float64(st.resets) / float64(st.attempts)

	// Port scan: many unique ports to relatively few IPs.
	if uPorts >= d.cfg.MaxDestPorts && uIPs <= d.cfg.MaxDestIPs {
		score := clamp01(0.5 + 0.5*float64(uPorts)/float64(d.cfg.MaxDestPorts*2))
		signals := []string{"high-unique-ports"}
		if synRatio >= d.cfg.SynRatio {
			score = clamp01(score + 0.1)
			signals = append(signals, "high-syn-only-ratio")
		}
		d.upsert(Finding{
			Type: FindingPortScan, Severity: sevFor(score), Score: score, Signals: signals,
			Namespace: st.key.namespace, Pod: st.key.pod, Workload: st.workload, Node: st.node, Comm: st.comm,
			UniqueDstIPs: uIPs, UniqueDstPorts: uPorts, Attempts: st.attempts, SYNOnly: st.synOnly, Resets: st.resets,
			FirstSeen: st.firstSeen, LastSeen: st.lastSeen,
		}, st.examples)
	}

	// Fan-out: many unique IPs to relatively few ports.
	if uIPs >= d.cfg.MaxDestIPs && uPorts <= d.cfg.MaxDestPorts {
		score := clamp01(0.5 + 0.5*float64(uIPs)/float64(d.cfg.MaxDestIPs*2))
		signals := []string{"high-unique-destinations"}
		if rstRatio >= d.cfg.ResetRatio {
			score = clamp01(score + 0.1)
			signals = append(signals, "high-reset-ratio")
		}
		d.upsert(Finding{
			Type: FindingFanOut, Severity: sevFor(score), Score: score, Signals: signals,
			Namespace: st.key.namespace, Pod: st.key.pod, Workload: st.workload, Node: st.node, Comm: st.comm,
			UniqueDstIPs: uIPs, UniqueDstPorts: uPorts, Attempts: st.attempts, SYNOnly: st.synOnly, Resets: st.resets,
			FirstSeen: st.firstSeen, LastSeen: st.lastSeen,
		}, st.examples)
	}

	// Lateral movement: wide IP + wide port coverage.
	if uIPs >= d.cfg.MaxDestIPs && uPorts >= d.cfg.MaxDestPorts {
		score := clamp01(0.7 + 0.3*float64(uIPs+uPorts)/float64(2*d.cfg.MaxDestIPs*2))
		d.upsert(Finding{
			Type: FindingLateral, Severity: sevFor(score), Score: score, Signals: []string{"wide-ip-and-port-coverage"},
			Namespace: st.key.namespace, Pod: st.key.pod, Workload: st.workload, Node: st.node, Comm: st.comm,
			UniqueDstIPs: uIPs, UniqueDstPorts: uPorts, Attempts: st.attempts, SYNOnly: st.synOnly, Resets: st.resets,
			FirstSeen: st.firstSeen, LastSeen: st.lastSeen,
		}, st.examples)
	}

	// SYN flood: high volume, SYN-only dominated.
	if synRatio >= d.cfg.SynRatio && st.attempts >= d.cfg.MinAttempts*5 {
		score := clamp01(0.5 + 0.5*synRatio)
		d.upsert(Finding{
			Type: FindingSYNFlood, Severity: sevFor(score), Score: score, Signals: []string{"syn-only-dominant", "high-volume"},
			Namespace: st.key.namespace, Pod: st.key.pod, Workload: st.workload, Node: st.node, Comm: st.comm,
			UniqueDstIPs: uIPs, UniqueDstPorts: uPorts, Attempts: st.attempts, SYNOnly: st.synOnly, Resets: st.resets,
			FirstSeen: st.firstSeen, LastSeen: st.lastSeen,
		}, st.examples)
	}
}

func (d *Detector) upsert(f Finding, examples []string) {
	f.ExampleDsts = append([]string(nil), examples...)
	key := findingKey{ftype: f.Type, ns: f.Namespace, pod: f.Pod}
	if prev, ok := d.findings[key]; ok {
		f.FirstSeen = prev.FirstSeen
		f.ID = prev.ID
	}
	if f.ID == "" {
		sum := sha256.Sum256([]byte(string(f.Type) + "|" + f.Namespace + "|" + f.Pod))
		f.ID = hex.EncodeToString(sum[:8])
	}
	cp := f
	d.findings[key] = &cp

	for len(d.findings) > d.cfg.MaxFindings {
		var oldestKey findingKey
		var oldest time.Time
		first := true
		for k, v := range d.findings {
			if first || v.LastSeen.Before(oldest) {
				oldestKey = k
				oldest = v.LastSeen
				first = false
			}
		}
		if first {
			return
		}
		delete(d.findings, oldestKey)
	}
}

func (d *Detector) evictIfNeeded() {
	for len(d.states) > d.cfg.MaxWorkloads && d.pos < len(d.order) {
		k := d.order[d.pos]
		d.pos++
		delete(d.states, k)
	}
	// Compact when the unread prefix grows too large.
	if d.pos > d.cfg.MaxWorkloads && d.pos == len(d.order) {
		d.order = d.order[:0]
		d.pos = 0
		for k := range d.states {
			d.order = append(d.order, k)
		}
	}
}

func clearState(st *state) {
	st.attempts = 0
	st.synOnly = 0
	st.resets = 0
	st.dstIPs = make(map[string]struct{})
	st.dstPorts = make(map[uint16]struct{})
	st.examples = st.examples[:0]
	st.firstSeen = time.Time{}
}

func normalize(c Config) Config {
	if c.Window <= 0 {
		c.Window = 60 * time.Second
	}
	if c.MaxDestIPs <= 0 {
		c.MaxDestIPs = 50
	}
	if c.MaxDestPorts <= 0 {
		c.MaxDestPorts = 50
	}
	if c.MinAttempts == 0 {
		c.MinAttempts = 20
	}
	if c.SynRatio == 0 {
		c.SynRatio = 0.8
	}
	if c.ResetRatio == 0 {
		c.ResetRatio = 0.5
	}
	if c.MaxWorkloads <= 0 {
		c.MaxWorkloads = 10000
	}
	if c.MaxDestPerWorkload <= 0 {
		c.MaxDestPerWorkload = 500
	}
	if c.FindingsTTL <= 0 {
		c.FindingsTTL = 10 * time.Minute
	}
	if c.MaxFindings <= 0 {
		c.MaxFindings = 2048
	}
	return c
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func sevFor(score float64) Severity {
	switch {
	case score >= 0.85:
		return SevCritical
	case score >= 0.65:
		return SevWarning
	default:
		return SevInfo
	}
}
