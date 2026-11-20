// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package workloadobs turns the per-flow, per-node cumulative counters that
// node agents report into per-workload monotonic counters, and feeds SLOs from
// the same deltas.
//
// Why it exists: agent counters are cumulative since a BPF map entry was
// created, per flow and per node. Summing them per workload on every scrape
// gives a number that drops when a pod dies, an entry is evicted, or an agent
// restarts, and Prometheus then reads each drop as a counter reset and adds
// the whole value back — rate() spikes. Instead the Tracker diffs each entry
// against its previous value, clamps resets, and accumulates the positive
// deltas, so the exported series only ever go up.
package workloadobs

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Counter indexes the per-workload counters.
type Counter int

const (
	Packets Counter = iota
	Bytes
	BlockedPackets
	ConnectionAttempts
	ConnectionsBlocked
	DNSQueries
	DNSFailures
	HTTPResponses
	HTTP5xx
	NumCounters
)

// CounterInfo names a counter for exposition.
type CounterInfo struct{ Name, Help string }

// Counters is the metadata for every Counter, in index order. Exported
// series are netra_workload_<Name>_total.
var Counters = [NumCounters]CounterInfo{
	Packets:            {"packets", "Packets observed for the workload."},
	Bytes:              {"bytes", "Bytes observed for the workload."},
	BlockedPackets:     {"blocked_packets", "Packets Netra blocked for the workload."},
	ConnectionAttempts: {"connection_attempts", "Socket connect/sendmsg attempts by the workload."},
	ConnectionsBlocked: {"connections_blocked", "Connection attempts Netra blocked for the workload."},
	DNSQueries:         {"dns_queries", "Cleartext UDP/53 DNS queries by the workload."},
	DNSFailures:        {"dns_failures", "Matched DNS responses with a non-zero rcode for the workload."},
	HTTPResponses:      {"http_responses", "Cleartext HTTP/1 responses seen for the workload."},
	HTTP5xx:            {"http_5xx", "Cleartext HTTP/1 5xx responses seen for the workload."},
}

// OtherLabel is the namespace and workload label value of the overflow series
// that aggregates every workload not admitted to the named set.
const OtherLabel = "__other__"

// Key identifies a workload as "namespace" plus "Kind/Name".
type Key struct{ Namespace, Workload string }

// Delta is one workload's growth since the previous Update.
type Delta struct {
	Key Key
	V   [NumCounters]uint64
}

func (d Delta) nonzero() bool {
	for _, v := range d.V {
		if v != 0 {
			return true
		}
	}
	return false
}

// NamedTotals is one admitted workload's running totals.
type NamedTotals struct {
	Key Key
	V   [NumCounters]uint64
}

// Snapshot is a consistent copy of the exportable state.
type Snapshot struct {
	Named    []NamedTotals // sorted by namespace, workload
	Other    [NumCounters]uint64
	MaxNamed int
	Entries  int    // raw agent entries currently tracked
	Dropped  uint64 // entries not tracked because the entry cap was reached
	// Truncated says, per source, whether any agent's latest report hit its
	// entry cap. Agents report top-N snapshots, so a capped source means
	// per-workload counts for it are lower bounds (the tail is invisible).
	Truncated map[string]bool
}

// Report sources, as named in Snapshot.Truncated and the exported gauge.
const (
	SourceFlows       = "flows"
	SourceConnections = "connections"
	SourceDNS         = "dns"
	SourceHTTP        = "http"
)

// Sources lists every source in a stable order.
var Sources = []string{SourceFlows, SourceConnections, SourceDNS, SourceHTTP}

// TrackerConfig bounds the Tracker's memory and cardinality.
type TrackerConfig struct {
	// MaxNamed caps distinct named workload series sets. Beyond it, new
	// workloads roll into the __other__ bucket. Default 100.
	MaxNamed int
	// IdleTimeout evicts a named workload with no activity for this long,
	// freeing its slot. Default 1h.
	IdleTimeout time.Duration
	// MaxEntries caps tracked raw agent entries. Default 500000.
	MaxEntries int
}

type entry struct {
	vals [3]uint64
	gen  uint32
}

type total struct {
	v          [NumCounters]uint64
	lastActive time.Time
}

// Tracker is safe for concurrent use.
type Tracker struct {
	cfg TrackerConfig

	mu        sync.Mutex
	gen       uint32
	prev      map[string]entry
	baselined map[string]bool // nodes for which prev holds a baseline
	dropped   uint64
	truncated map[string]bool
	named     map[Key]*total
	other     [NumCounters]uint64
}

// keepGens is how many updates an entry may go unreported before it is
// forgotten. Forgotten entries that reappear count as new.
const keepGens = 10

func NewTracker(cfg TrackerConfig) *Tracker {
	if cfg.MaxNamed <= 0 {
		cfg.MaxNamed = 100
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = time.Hour
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 500000
	}
	return &Tracker{
		cfg:       cfg,
		prev:      map[string]entry{},
		baselined: map[string]bool{},
		truncated: map[string]bool{},
		named:     map[Key]*total{},
	}
}

// Update ingests the agents' current cumulative counters and returns each
// workload's growth since the previous call, sorted by workload.
//
// The first report from a node only establishes a baseline (no delta): its
// counters describe history, not growth. The same applies to a node that
// returns after being stale or absent, so a long-idle agent reconnecting does
// not book its whole lifetime as one tick. Entries that first appear after the
// baseline count in full, because they were created since the last look.
func (t *Tracker) Update(agents []models.AgentStatus, now time.Time) []Delta {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gen++

	acc := map[Key]*Delta{}
	seenNodes := map[string]bool{}
	truncatedNow := map[string]bool{}

	for _, a := range agents {
		if a.Stale {
			continue
		}
		node := a.Node
		seenNodes[node] = true
		seeding := !t.baselined[node]

		// observe folds one raw entry in. truncated says the source's list hit
		// its agent-side cap: the agent reports a top-N snapshot, so an entry
		// that first appears may just have climbed into the top N with a long
		// history. Counting all of it would book that history as growth, so
		// for a capped source a first sighting only sets a baseline. (The cost
		// is that a genuinely new flow's first, small, report is not counted.)
		observe := func(kind byte, ek string, key Key, ok bool, status uint16, vals [3]uint64, truncated bool) {
			e, had := t.prev[ek]
			var d [3]uint64
			switch {
			case seeding:
				// Baseline only, even if an older value is on file: a node
				// that was stale or absent and returns holds lifetime
				// totals, not growth since we last looked.
				if !had && len(t.prev) >= t.cfg.MaxEntries {
					t.dropped++
					return
				}
			case !had:
				if len(t.prev) >= t.cfg.MaxEntries {
					t.dropped++
					return
				}
				if !truncated {
					d = vals // created since the last look: all of it is new growth
				}
			default:
				for i := range vals {
					if vals[i] >= e.vals[i] {
						d[i] = vals[i] - e.vals[i]
					} else {
						d[i] = vals[i] // counter reset: it restarted from zero
					}
				}
			}
			t.prev[ek] = entry{vals: vals, gen: t.gen}
			if !ok || d == [3]uint64{} {
				return
			}
			dl := acc[key]
			if dl == nil {
				dl = &Delta{Key: key}
				acc[key] = dl
			}
			applyDelta(&dl.V, kind, status, d)
		}

		flowsCapped := len(a.Stats) >= models.ReportCapFlows
		for _, s := range a.Stats {
			key, ok := workloadKey(s.Namespace, s.WorkloadKind, s.WorkloadName, s.Pod)
			observe('D', entryKey(node, 'D', u64(s.CgroupID), s.Hook, s.Direction, s.Protocol, s.SourceIP, u64(uint64(s.SourcePort)), s.DestinationIP, u64(uint64(s.Port))),
				key, ok, 0, [3]uint64{s.Packets, s.Bytes, s.Blocked}, flowsCapped)
		}
		connCapped := len(a.ConnectionAttempts) >= models.ReportCapConnAttempts
		for _, s := range a.ConnectionAttempts {
			key, ok := workloadKey(s.Namespace, s.WorkloadKind, s.WorkloadName, s.Pod)
			observe('C', entryKey(node, 'C', u64(s.CgroupID), s.Family, s.Protocol, s.RemoteIP, u64(uint64(s.RemotePort))),
				key, ok, 0, [3]uint64{s.Attempts, s.Blocked, 0}, connCapped)
		}
		dnsCapped := len(a.DNSHealth) >= models.ReportCapDNS
		for _, s := range a.DNSHealth {
			key, ok := workloadKey(s.Namespace, s.WorkloadKind, s.WorkloadName, s.Pod)
			observe('N', entryKey(node, 'N', u64(s.CgroupID), s.Name),
				key, ok, 0, [3]uint64{s.Queries, s.Failures, 0}, dnsCapped)
		}
		httpCapped := len(a.HTTPStatus) >= models.ReportCapHTTPStatus
		for _, s := range a.HTTPStatus {
			key, ok := workloadKey(s.Namespace, s.WorkloadKind, s.WorkloadName, s.Pod)
			observe('H', entryKey(node, 'H', u64(s.CgroupID), u64(uint64(s.Status))),
				key, ok, s.Status, [3]uint64{s.Count, 0, 0}, httpCapped)
		}
		if flowsCapped {
			truncatedNow[SourceFlows] = true
		}
		if connCapped {
			truncatedNow[SourceConnections] = true
		}
		if dnsCapped {
			truncatedNow[SourceDNS] = true
		}
		if httpCapped {
			truncatedNow[SourceHTTP] = true
		}
	}

	t.truncated = truncatedNow

	// A node absent this round loses its baseline, so it re-seeds on return.
	for n := range t.baselined {
		if !seenNodes[n] {
			delete(t.baselined, n)
		}
	}
	for n := range seenNodes {
		t.baselined[n] = true
	}
	for k, e := range t.prev {
		if t.gen-e.gen > keepGens {
			delete(t.prev, k)
		}
	}

	deltas := make([]Delta, 0, len(acc))
	for _, d := range acc {
		if d.nonzero() {
			deltas = append(deltas, *d)
		}
	}
	sort.Slice(deltas, func(i, j int) bool {
		if deltas[i].Key.Namespace != deltas[j].Key.Namespace {
			return deltas[i].Key.Namespace < deltas[j].Key.Namespace
		}
		return deltas[i].Key.Workload < deltas[j].Key.Workload
	})

	t.evictIdle(now)
	t.account(deltas, now)
	return deltas
}

// evictIdle frees the slots of named workloads with no recent activity.
func (t *Tracker) evictIdle(now time.Time) {
	for k, tot := range t.named {
		if now.Sub(tot.lastActive) > t.cfg.IdleTimeout {
			delete(t.named, k)
		}
	}
}

// account folds deltas into the named totals or the overflow bucket. Workloads
// already named always stay named (stable series). New ones are admitted busiest
// first while slots remain; the rest accumulate in __other__.
func (t *Tracker) account(deltas []Delta, now time.Time) {
	var fresh []Delta
	for _, d := range deltas {
		if tot, ok := t.named[d.Key]; ok {
			addInto(&tot.v, d.V)
			tot.lastActive = now
			continue
		}
		fresh = append(fresh, d)
	}
	sort.SliceStable(fresh, func(i, j int) bool {
		if fresh[i].V[Packets] != fresh[j].V[Packets] {
			return fresh[i].V[Packets] > fresh[j].V[Packets]
		}
		return fresh[i].V[Bytes] > fresh[j].V[Bytes]
	})
	for _, d := range fresh {
		if len(t.named) < t.cfg.MaxNamed {
			tot := &total{lastActive: now}
			addInto(&tot.v, d.V)
			t.named[d.Key] = tot
			continue
		}
		addInto(&t.other, d.V)
	}
}

// Snapshot returns a copy of the exportable state.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Snapshot{Other: t.other, MaxNamed: t.cfg.MaxNamed, Entries: len(t.prev), Dropped: t.dropped, Truncated: map[string]bool{}}
	for _, src := range Sources {
		s.Truncated[src] = t.truncated[src]
	}
	s.Named = make([]NamedTotals, 0, len(t.named))
	for k, tot := range t.named {
		s.Named = append(s.Named, NamedTotals{Key: k, V: tot.v})
	}
	sort.Slice(s.Named, func(i, j int) bool {
		if s.Named[i].Key.Namespace != s.Named[j].Key.Namespace {
			return s.Named[i].Key.Namespace < s.Named[j].Key.Namespace
		}
		return s.Named[i].Key.Workload < s.Named[j].Key.Workload
	})
	return s
}

func applyDelta(dst *[NumCounters]uint64, kind byte, status uint16, d [3]uint64) {
	switch kind {
	case 'D':
		dst[Packets] += d[0]
		dst[Bytes] += d[1]
		dst[BlockedPackets] += d[2]
	case 'C':
		dst[ConnectionAttempts] += d[0]
		dst[ConnectionsBlocked] += d[1]
	case 'N':
		dst[DNSQueries] += d[0]
		dst[DNSFailures] += d[1]
	case 'H':
		dst[HTTPResponses] += d[0]
		if status >= 500 && status <= 599 {
			dst[HTTP5xx] += d[0]
		}
	}
}

func addInto(dst *[NumCounters]uint64, src [NumCounters]uint64) {
	for i := range src {
		dst[i] += src[i]
	}
}

// workloadKey names the workload an agent entry belongs to. Entries with no
// resolved workload (host processes, unresolved cgroups) have none and are
// left out; the aggregate netra_* metrics already cover them.
func workloadKey(ns, kind, name, pod string) (Key, bool) {
	switch {
	case name != "":
		kind, name = canonicalOwner(kind, name)
		if kind != "" {
			return Key{ns, kind + "/" + name}, true
		}
		return Key{ns, name}, true
	case pod != "":
		return Key{ns, "Pod/" + pod}, true
	default:
		return Key{}, false
	}
}

var (
	// A Deployment's ReplicaSet is named <deployment>-<pod-template-hash>; the
	// hash is 5-10 characters of Kubernetes' vowel-free "safe" alphabet.
	replicaSetHashRE = regexp.MustCompile(`^(.+)-[bcdfghjklmnpqrstvwxz2456789]{5,10}$`)
	// A CronJob's Job is named <cronjob>-<scheduled time in minutes> (8-10 digits).
	cronJobRunRE = regexp.MustCompile(`^(.+)-[0-9]{8,10}$`)
)

// canonicalOwner maps the immediate owner the agent resolves to the workload
// an operator thinks in. Agents report the pod's direct controller, so a
// Deployment's pods appear as ReplicaSet "checkout-6c4b4dfd7c": a different
// name after every rollout, which would fragment series and make a per-workload
// SLO impossible to write. Mapping ReplicaSet -> Deployment and Job -> CronJob
// by their generated-name suffixes keeps one stable identity. A bare
// ReplicaSet or Job whose name happens not to fit the pattern is left alone.
func canonicalOwner(kind, name string) (string, string) {
	switch kind {
	case "ReplicaSet":
		if m := replicaSetHashRE.FindStringSubmatch(name); m != nil {
			return "Deployment", m[1]
		}
	case "Job":
		if m := cronJobRunRE.FindStringSubmatch(name); m != nil {
			return "CronJob", m[1]
		}
	}
	return kind, name
}

func entryKey(node string, kind byte, parts ...string) string {
	var b strings.Builder
	b.Grow(len(node) + 2 + 16*len(parts))
	b.WriteString(node)
	b.WriteByte(0)
	b.WriteByte(kind)
	for _, p := range parts {
		b.WriteByte(0)
		b.WriteString(p)
	}
	return b.String()
}

func u64(v uint64) string { return strconv.FormatUint(v, 10) }
