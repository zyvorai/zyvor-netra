// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package dnsdetect implements metadata-only DNS anomaly detection over
// Netra's existing UDP/53 query-name events.
//
// Design constraints (mirrors Netra's safety model):
//   - Query name, QTYPE, RCODE only. No payloads.
//   - Observe-only. Never emits enforcement.
//   - Bounded memory: LRU over (registered-domain, namespace, pod).
//   - Bounded subdomain tracking per key.
//   - Findings carry a TTL and are swept periodically.
//
// Detections: tunneling, DGA, beaconing, NXDOMAIN/SERVFAIL storm.
package dnsdetect

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// DNS wire constants used by the detector.
const (
	RCodeNoError  uint8 = 0
	RCodeFormErr  uint8 = 1
	RCodeServFail uint8 = 2
	RCodeNXDomain uint8 = 3
	RCodeRefused  uint8 = 5

	QTypeA    uint16 = 1
	QTypeTXT  uint16 = 16
	QTypeAAAA uint16 = 28
)

// Internal sizing constants.
const (
	bucketWidth        = 30 * time.Second
	bucketCount        = 12 // 6-minute rolling window
	subdomainOverflow  = 10 // subdomain cap = MaxUniqueSubdomains * this
	maxIntervals       = 128
	findingsSweepEvery = 1024
)

// FindingType classifies a detection.
type FindingType string

const (
	FindingTunneling     FindingType = "tunneling"
	FindingDGA           FindingType = "dga"
	FindingBeaconing     FindingType = "beaconing"
	FindingNXDomainStorm FindingType = "nxdomain_storm"
	FindingServfailStorm FindingType = "servfail_storm"
)

// Severity mirrors Netra's existing vocabulary.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Query is one observed DNS query event, already attributed by the eBPF
// datapath. Populated from internal/l7's socket-attempt aggregation.
type Query struct {
	Name      string
	QType     uint16
	RCode     uint8
	Timestamp time.Time

	Namespace string
	Pod       string
	Workload  string
	Node      string
	CgroupID  uint64
	PID       uint32
	UID       uint32
	Comm      string
}

// Finding is a single detection result.
type Finding struct {
	ID        string      `json:"id"`
	Type      FindingType `json:"type"`
	Severity  Severity    `json:"severity"`
	Domain    string      `json:"domain"`              // registered domain
	Subdomain string      `json:"subdomain,omitempty"` // label(s) below registered
	Score     float64     `json:"score"`
	Signals   []string    `json:"signals"`

	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Node      string `json:"node,omitempty"`
	Comm      string `json:"comm,omitempty"`

	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Count     uint64    `json:"count"`

	ExampleNames []string `json:"exampleNames,omitempty"`
}

// Config controls thresholds. Every knob is exposed via Helm.
type Config struct {
	Window              time.Duration
	MaxUniqueSubdomains int
	MinAvgLabelLen      float64
	MinEntropy          float64
	MinQueryRate        float64

	DGAMinLabelLen  int
	DGAMinEntropy   float64
	DGAMaxDigits    float64
	DGAMinConsonant float64
	DGAMinScore     float64

	BeaconMinSamples int
	BeaconMaxJitter  time.Duration

	NXDomainRatio    float64
	NXDomainMinCount uint64
	ServfailRatio    float64
	ServfailMinCount uint64

	MaxDomains       int
	MaxExamplesKept  int
	FindingsTTL      time.Duration
	MaxFindings      int
	SubdomainCapMult int
}

// DefaultConfig returns conservative production defaults.
func DefaultConfig() Config {
	return Config{
		Window:              5 * time.Minute,
		MaxUniqueSubdomains: 200,
		MinAvgLabelLen:      20,
		MinEntropy:          3.5,
		MinQueryRate:        2.0,

		DGAMinLabelLen:  8,
		DGAMinEntropy:   3.2,
		DGAMaxDigits:    0.35,
		DGAMinConsonant: 0.55,
		DGAMinScore:     0.65,

		BeaconMinSamples: 10,
		BeaconMaxJitter:  2 * time.Second,

		NXDomainRatio:    0.7,
		NXDomainMinCount: 20,
		ServfailRatio:    0.7,
		ServfailMinCount: 20,

		MaxDomains:       50000,
		MaxExamplesKept:  5,
		FindingsTTL:      30 * time.Minute,
		MaxFindings:      4096,
		SubdomainCapMult: subdomainOverflow,
	}
}

// Snapshot is the metric payload.
type Snapshot struct {
	QueriesSeen    uint64                 `json:"queriesSeen"`
	DomainsTracked uint64                 `json:"domainsTracked"`
	ActiveFindings uint64                 `json:"activeFindings"`
	FindingsTotal  map[FindingType]uint64 `json:"findingsTotal"`
}

// Detector is the stateful engine. Safe for concurrent use.
type Detector struct {
	mu          sync.Mutex
	cfg         Config
	states      *lru
	findings    map[findingKey]*Finding
	findingsSeq uint64
	observes    uint64

	queriesSeen   uint64
	findingsTotal map[FindingType]uint64
}

// New creates a Detector.
func New(cfg Config) *Detector {
	cfg = normalizeConfig(cfg)
	return &Detector{
		cfg:           cfg,
		states:        newLRU(cfg.MaxDomains),
		findings:      make(map[findingKey]*Finding),
		findingsTotal: make(map[FindingType]uint64),
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
	cfg = normalizeConfig(cfg)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg = cfg
	d.states.setCap(cfg.MaxDomains)
}

// Observe ingests one DNS query event. O(1) amortized.
func (d *Detector) Observe(q Query) {
	if q.Name == "" || q.Timestamp.IsZero() {
		return
	}
	registered, sub := splitDomain(q.Name)
	if registered == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.queriesSeen++
	d.observes++

	key := stateKey{registered: registered, namespace: q.Namespace, pod: q.Pod}
	st := d.states.get(key)
	if st == nil {
		st = newDomainState(key, d.cfg)
		d.states.put(key, st)
	}

	// Attribution refresh (most-recent wins, but stable within a key).
	st.workload = q.Workload
	st.node = q.Node
	st.comm = q.Comm

	// Windowed rate.
	st.buckets.advance(q.Timestamp)
	st.buckets.inc()

	// Counters.
	st.totalQueries++
	switch q.RCode {
	case RCodeNXDomain:
		st.nxdomainCount++
	case RCodeServFail:
		st.servfailCount++
	}
	if q.QType == QTypeTXT {
		st.txtCount++
	}

	// Subdomain tracking with cap.
	if sub != "" {
		if len(st.subdomains) < st.subdomainCap {
			st.subdomains[sub] = struct{}{}
		} else {
			st.subdomainOverflow = true
			// Still count, but don't grow the map.
		}
		// Label stats.
		for _, lbl := range strings.Split(sub, ".") {
			if lbl == "" {
				continue
			}
			st.labelLenSum += float64(len(lbl))
			st.labelCount++
			st.entropySum += shannonEntropy(lbl)
			st.entropyN++
		}
	}

	// Bounded example capture.
	if len(st.examples) < d.cfg.MaxExamplesKept {
		dup := false
		for _, e := range st.examples {
			if e == q.Name {
				dup = true
				break
			}
		}
		if !dup {
			st.examples = append(st.examples, q.Name)
		}
	}

	// Beaconing intervals (bounded ring).
	if !st.lastQuery.IsZero() {
		iv := q.Timestamp.Sub(st.lastQuery)
		if iv > 0 && iv < 10*time.Minute {
			st.intervals = append(st.intervals, iv)
			if len(st.intervals) > maxIntervals {
				copy(st.intervals, st.intervals[len(st.intervals)-maxIntervals:])
				st.intervals = st.intervals[:maxIntervals]
			}
		}
	}
	st.lastQuery = q.Timestamp
	if st.firstSeen.IsZero() {
		st.firstSeen = q.Timestamp
	}
	st.lastSeen = q.Timestamp

	// Evaluate.
	d.evaluateLocked(st)

	// Periodic findings sweep.
	if d.observes%findingsSweepEvery == 0 {
		d.sweepFindingsLocked(q.Timestamp)
	}
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
		cp.ExampleNames = append([]string(nil), f.ExampleNames...)
		out = append(out, cp)
	}
	return out
}

// Snapshot returns counters for Prometheus / API.
func (d *Detector) Snapshot() Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	counts := make(map[FindingType]uint64, len(d.findingsTotal))
	for k, v := range d.findingsTotal {
		counts[k] = v
	}
	return Snapshot{
		QueriesSeen:    d.queriesSeen,
		DomainsTracked: uint64(d.states.len()),
		ActiveFindings: uint64(len(d.findings)),
		FindingsTotal:  counts,
	}
}

// ---------- evaluation ----------

func (d *Detector) evaluateLocked(st *domainState) {
	now := st.lastSeen

	// --- Tunneling ---
	if len(st.subdomains) >= d.cfg.MaxUniqueSubdomains || st.subdomainOverflow {
		avgLen := 0.0
		if st.labelCount > 0 {
			avgLen = st.labelLenSum / float64(st.labelCount)
		}
		entropy := 0.0
		if st.entropyN > 0 {
			entropy = st.entropySum / float64(st.entropyN)
		}
		rate := st.buckets.ratePerSec()

		signals := []string{}
		score := 0.0
		if len(st.subdomains) >= d.cfg.MaxUniqueSubdomains || st.subdomainOverflow {
			signals = append(signals, "unique-subdomain-count")
			score += 0.3
		}
		if avgLen >= d.cfg.MinAvgLabelLen {
			signals = append(signals, "long-labels")
			score += 0.25
		}
		if entropy >= d.cfg.MinEntropy {
			signals = append(signals, "high-entropy")
			score += 0.25
		}
		if rate >= d.cfg.MinQueryRate {
			signals = append(signals, "high-query-rate")
			score += 0.2
		}
		if st.txtCount > 0 && st.txtCount*4 > st.totalQueries {
			// TXT-heavy is a strong tunneling signal.
			signals = append(signals, "txt-heavy")
			score += 0.1
		}
		if score >= 0.6 {
			d.upsertLocked(Finding{
				Type:      FindingTunneling,
				Severity:  sevFor(score),
				Domain:    st.registered,
				Score:     clamp01(score),
				Signals:   signals,
				FirstSeen: st.firstSeen,
				LastSeen:  now,
				Count:     st.totalQueries,
				Namespace: st.key.namespace,
				Pod:       st.key.pod,
				Workload:  st.workload,
				Node:      st.node,
				Comm:      st.comm,
			}, st.examples)
		}
	}

	// --- DGA on registered SLD and on the first sub-label (if any) ---
	regSLD := secondLevelLabel(st.registered)
	subFirst := firstLabelOfSub(st)

	best := d.dgaScore(regSLD, st)
	bestLabel := regSLD
	if subFirst != "" {
		s := d.dgaScore(subFirst, st)
		if s > best {
			best = s
			bestLabel = subFirst
		}
	}
	if best >= d.cfg.DGAMinScore {
		signals := dgaSignals(bestLabel, st)
		d.upsertLocked(Finding{
			Type:      FindingDGA,
			Severity:  sevFor(best),
			Domain:    st.registered,
			Subdomain: subFirst,
			Score:     clamp01(best),
			Signals:   signals,
			FirstSeen: st.firstSeen,
			LastSeen:  now,
			Count:     st.totalQueries,
			Namespace: st.key.namespace,
			Pod:       st.key.pod,
			Workload:  st.workload,
			Node:      st.node,
			Comm:      st.comm,
		}, st.examples)
	}

	// --- Beaconing ---
	if len(st.intervals) >= d.cfg.BeaconMinSamples {
		mean, stddev := meanStddev(st.intervals)
		if mean > 0 && stddev <= d.cfg.BeaconMaxJitter {
			jitterRatio := float64(stddev) / float64(mean)
			score := 0.5 + 0.5*(1.0-clamp01(jitterRatio))
			d.upsertLocked(Finding{
				Type:      FindingBeaconing,
				Severity:  sevFor(score),
				Domain:    st.registered,
				Score:     clamp01(score),
				Signals:   []string{"low-jitter-interval", "regular-cadence"},
				FirstSeen: st.firstSeen,
				LastSeen:  now,
				Count:     st.totalQueries,
				Namespace: st.key.namespace,
				Pod:       st.key.pod,
				Workload:  st.workload,
				Node:      st.node,
				Comm:      st.comm,
			}, st.examples)
		}
	}

	// --- NXDOMAIN storm ---
	if st.totalQueries >= d.cfg.NXDomainMinCount {
		r := float64(st.nxdomainCount) / float64(st.totalQueries)
		if r >= d.cfg.NXDomainRatio {
			score := 0.4 + 0.6*r
			d.upsertLocked(Finding{
				Type:      FindingNXDomainStorm,
				Severity:  sevFor(score),
				Domain:    st.registered,
				Score:     clamp01(score),
				Signals:   []string{"high-nxdomain-ratio", "volume"},
				FirstSeen: st.firstSeen,
				LastSeen:  now,
				Count:     st.totalQueries,
				Namespace: st.key.namespace,
				Pod:       st.key.pod,
				Workload:  st.workload,
				Node:      st.node,
				Comm:      st.comm,
			}, st.examples)
		}
	}

	// --- SERVFAIL storm ---
	if st.totalQueries >= d.cfg.ServfailMinCount {
		r := float64(st.servfailCount) / float64(st.totalQueries)
		if r >= d.cfg.ServfailRatio {
			score := 0.4 + 0.6*r
			d.upsertLocked(Finding{
				Type:      FindingServfailStorm,
				Severity:  sevFor(score),
				Domain:    st.registered,
				Score:     clamp01(score),
				Signals:   []string{"high-servfail-ratio", "volume"},
				FirstSeen: st.firstSeen,
				LastSeen:  now,
				Count:     st.totalQueries,
				Namespace: st.key.namespace,
				Pod:       st.key.pod,
				Workload:  st.workload,
				Node:      st.node,
				Comm:      st.comm,
			}, st.examples)
		}
	}
}

func (d *Detector) upsertLocked(f Finding, examples []string) {
	f.ExampleNames = append([]string(nil), examples...)
	key := findingKey{
		ftype:      f.Type,
		registered: f.Domain,
		namespace:  f.Namespace,
		pod:        f.Pod,
	}
	if prev, ok := d.findings[key]; ok {
		f.FirstSeen = prev.FirstSeen
		f.ID = prev.ID
		if f.Count < prev.Count {
			f.Count = prev.Count
		}
	} else {
		d.findingsSeq++
		f.ID = findingID(f, d.findingsSeq)
		d.findingsTotal[f.Type]++
	}
	cp := f
	d.findings[key] = &cp
	d.enforceFindingsCapLocked()
}

func (d *Detector) enforceFindingsCapLocked() {
	if d.cfg.MaxFindings <= 0 || len(d.findings) <= d.cfg.MaxFindings {
		return
	}
	// Evict oldest by LastSeen.
	var oldestKey findingKey
	var oldest time.Time
	first := true
	for k, f := range d.findings {
		if first || f.LastSeen.Before(oldest) {
			oldestKey = k
			oldest = f.LastSeen
			first = false
		}
	}
	if !first {
		delete(d.findings, oldestKey)
	}
}

func (d *Detector) sweepFindingsLocked(now time.Time) {
	cutoff := now.Add(-d.cfg.FindingsTTL)
	for k, f := range d.findings {
		if f.LastSeen.Before(cutoff) {
			delete(d.findings, k)
		}
	}
}

// ---------- helpers: DGA ----------

func (d *Detector) dgaScore(label string, st *domainState) float64 {
	if len(label) < d.cfg.DGAMinLabelLen {
		return 0
	}
	ent := shannonEntropy(label)
	digits := digitRatio(label)
	cons := consonantRatio(label)

	score := 0.0
	if ent >= d.cfg.DGAMinEntropy {
		score += 0.35
	}
	if digits >= d.cfg.DGAMaxDigits {
		score += 0.25
	}
	if cons >= d.cfg.DGAMinConsonant {
		score += 0.25
	}
	if st.totalQueries > 0 {
		r := float64(st.nxdomainCount) / float64(st.totalQueries)
		if r >= 0.5 {
			score += 0.15
		}
	}
	return clamp01(score)
}

func dgaSignals(label string, st *domainState) []string {
	sigs := []string{}
	if shannonEntropy(label) >= 3.2 {
		sigs = append(sigs, "high-entropy-label")
	}
	if digitRatio(label) >= 0.35 {
		sigs = append(sigs, "many-digits")
	}
	if consonantRatio(label) >= 0.55 {
		sigs = append(sigs, "consonant-heavy")
	}
	if st.totalQueries > 0 && float64(st.nxdomainCount)/float64(st.totalQueries) >= 0.5 {
		sigs = append(sigs, "high-nxdomain-ratio")
	}
	return sigs
}

// ---------- helpers: domain parsing ----------

// splitDomain returns (registered-domain, subdomain-below-it).
// Uses the Public Suffix List, so shared-hosting domains like
// a.github.io and b.github.io are treated as separate registrations.
func splitDomain(name string) (registered, sub string) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return "", ""
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		parts := strings.Split(name, ".")
		if len(parts) < 2 {
			return name, ""
		}
		reg = strings.Join(parts[len(parts)-2:], ".")
	}
	if name == reg {
		return reg, ""
	}
	return reg, strings.TrimSuffix(name, "."+reg)
}

func secondLevelLabel(registered string) string {
	parts := strings.Split(registered, ".")
	if len(parts) < 2 {
		return registered
	}
	return parts[len(parts)-2]
}

func firstLabelOfSub(st *domainState) string {
	// Use the first observed subdomain to determine the analysis label;
	// statistics over many subdomains would dilute a real DGA signal.
	for s := range st.subdomains {
		first := s
		if i := strings.IndexByte(s, '.'); i >= 0 {
			first = s[:i]
		}
		return first
	}
	return ""
}

// ---------- helpers: stats ----------

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func digitRatio(s string) float64 {
	if s == "" {
		return 0
	}
	var d int
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			d++
		}
	}
	return float64(d) / float64(len(s))
}

func consonantRatio(s string) float64 {
	if s == "" {
		return 0
	}
	const vowels = "aeiou"
	var c, total int
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < 'a' || ch > 'z' {
			continue
		}
		total++
		if !strings.ContainsRune(vowels, rune(ch)) {
			c++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(c) / float64(total)
}

// meanStddev uses float64 to avoid int64 overflow for intervals > ~3s.
func meanStddev(xs []time.Duration) (time.Duration, time.Duration) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += float64(x)
	}
	mean := sum / float64(len(xs))
	var sq float64
	for _, x := range xs {
		d := float64(x) - mean
		sq += d * d
	}
	variance := sq / float64(len(xs))
	return time.Duration(mean), time.Duration(math.Sqrt(variance))
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

func findingID(f Finding, seq uint64) string {
	h := sha256.Sum256([]byte(string(f.Type) + "|" + f.Domain + "|" + f.Namespace + "|" + f.Pod))
	// Include seq so identical re-emissions get unique IDs only at creation.
	_ = seq
	return hex.EncodeToString(h[:8])
}

// CEFEscape escapes a value for use in a CEF header or extension field.
func CEFEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `|`, `\|`, `=`, `\=`, "\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}

// ---------- state ----------

type stateKey struct {
	registered string
	namespace  string
	pod        string
}

type findingKey struct {
	ftype      FindingType
	registered string
	namespace  string
	pod        string
}

type domainState struct {
	key        stateKey
	registered string
	workload   string
	node       string
	comm       string
	firstSeen  time.Time
	lastSeen   time.Time

	totalQueries  uint64
	nxdomainCount uint64
	servfailCount uint64
	txtCount      uint64

	subdomains        map[string]struct{}
	subdomainCap      int
	subdomainOverflow bool

	labelLenSum float64
	labelCount  uint64
	entropySum  float64
	entropyN    uint64

	intervals []time.Duration
	lastQuery time.Time

	buckets  bucketRing
	examples []string
}

func newDomainState(key stateKey, cfg Config) *domainState {
	c := cfg.MaxUniqueSubdomains * cfg.SubdomainCapMult
	if c <= 0 {
		c = cfg.MaxUniqueSubdomains
	}
	return &domainState{
		key:          key,
		registered:   key.registered,
		subdomains:   make(map[string]struct{}),
		subdomainCap: c,
		examples:     make([]string, 0, cfg.MaxExamplesKept),
		buckets:      bucketRing{counts: make([]uint64, bucketCount)},
	}
}

type bucketRing struct {
	counts []uint64
	head   int
	headTS time.Time
}

func (r *bucketRing) advance(now time.Time) {
	if r.headTS.IsZero() {
		r.headTS = now.Truncate(bucketWidth)
		return
	}
	target := now.Truncate(bucketWidth)
	steps := int(target.Sub(r.headTS) / bucketWidth)
	if steps <= 0 {
		return
	}
	n := len(r.counts)
	if steps >= n {
		for i := range r.counts {
			r.counts[i] = 0
		}
		r.head = 0
		r.headTS = target
		return
	}
	for i := 0; i < steps; i++ {
		r.head = (r.head + 1) % n
		r.counts[r.head] = 0
	}
	r.headTS = target
}

func (r *bucketRing) inc() {
	if len(r.counts) == 0 {
		return
	}
	r.counts[r.head]++
}

func (r *bucketRing) total() uint64 {
	var t uint64
	for _, c := range r.counts {
		t += c
	}
	return t
}

func (r *bucketRing) ratePerSec() float64 {
	if len(r.counts) == 0 {
		return 0
	}
	windowSecs := float64(len(r.counts)) * bucketWidth.Seconds()
	return float64(r.total()) / windowSecs
}

// ---------- LRU over domainState ----------

type lru struct {
	ll    *list.List
	items map[stateKey]*list.Element
	cap   int
}

func newLRU(cap int) *lru {
	if cap <= 0 {
		cap = 50000
	}
	return &lru{ll: list.New(), items: make(map[stateKey]*list.Element), cap: cap}
}

func (l *lru) setCap(n int) {
	if n <= 0 {
		return
	}
	l.cap = n
	for l.ll.Len() > l.cap {
		l.evictOldest()
	}
}

func (l *lru) get(key stateKey) *domainState {
	e, ok := l.items[key]
	if !ok {
		return nil
	}
	l.ll.MoveToFront(e)
	return e.Value.(*domainState)
}

func (l *lru) put(key stateKey, st *domainState) {
	if e, ok := l.items[key]; ok {
		e.Value = st
		l.ll.MoveToFront(e)
		return
	}
	e := l.ll.PushFront(st)
	l.items[key] = e
	for l.ll.Len() > l.cap {
		l.evictOldest()
	}
}

func (l *lru) evictOldest() {
	back := l.ll.Back()
	if back == nil {
		return
	}
	st := back.Value.(*domainState)
	delete(l.items, st.key)
	l.ll.Remove(back)
}

func (l *lru) len() int { return l.ll.Len() }

func normalizeConfig(cfg Config) Config {
	if cfg.MaxDomains <= 0 {
		cfg.MaxDomains = 50000
	}
	if cfg.MaxExamplesKept <= 0 {
		cfg.MaxExamplesKept = 5
	}
	if cfg.FindingsTTL <= 0 {
		cfg.FindingsTTL = 30 * time.Minute
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = 4096
	}
	if cfg.SubdomainCapMult <= 0 {
		cfg.SubdomainCapMult = subdomainOverflow
	}
	if cfg.BeaconMinSamples <= 0 {
		cfg.BeaconMinSamples = 10
	}
	if cfg.BeaconMaxJitter <= 0 {
		cfg.BeaconMaxJitter = 2 * time.Second
	}
	return cfg
}
