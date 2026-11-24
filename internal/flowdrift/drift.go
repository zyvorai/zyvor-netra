// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package flowdrift compares what each workload talked to (and how much) in a
// recent window against an earlier baseline window of the retained flow
// history (internal/flowlog). It reports dependency edges that are new or have
// gone quiet, and per-workload byte-rate surges and drops. It reads only the
// records it is handed: no new collector, no payloads, nothing is applied.
//
// Absence from the history is not proof that a connection never happened: the
// history is bounded in age and rows, and a baseline shorter than MinBaseline
// is reported as not ready rather than guessed from.
package flowdrift

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

// Schema names the dependency drift report.
const Schema = "netra-dependency-drift/1"

// Bounds and defaults.
const (
	DefaultRecent   = time.Hour
	MinRecent       = time.Minute
	MaxRecent       = 48 * time.Hour
	DefaultBaseline = 6 * 24 * time.Hour
	MaxBaseline     = 14 * 24 * time.Hour
	// DefaultMinBaseline is how much history before the recent window must
	// exist before "new" means anything.
	DefaultMinBaseline = time.Hour
	DefaultLimit       = 100
	MaxLimit           = 500
	// MinVanishedObservations keeps one-off baseline edges from being reported as gone.
	MinVanishedObservations = 3
	maxEdges                = 200000
)

// Options select the windows and bounds.
type Options struct {
	Now         time.Time
	Recent      time.Duration
	Baseline    time.Duration
	MinBaseline time.Duration
	PublicOnly  bool // only report edges whose peer is a public address
	Limit       int
	// Truncated says the record set was cut (oldest rows dropped first).
	Truncated bool
}

// Window is a half-open time range.
type Window struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Edge is one workload-to-peer dependency.
type Edge struct {
	Namespace    string `json:"namespace,omitempty"`
	Workload     string `json:"workload"`
	Direction    string `json:"direction,omitempty"`
	Peer         string `json:"peer"`
	PeerClass    string `json:"peerClass"` // public, private, name
	Port         uint16 `json:"port"`
	Protocol     string `json:"protocol,omitempty"`
	AppProtocol  string `json:"appProtocol,omitempty"`
	Name         string `json:"name,omitempty"` // DNS name or SNI joined by the agent, when seen
	Bytes        uint64 `json:"bytes"`
	Packets      uint64 `json:"packets,omitempty"`
	Observations int    `json:"observations"`
	FirstSeen    string `json:"firstSeen"`
	LastSeen     string `json:"lastSeen"`
	Attention    bool   `json:"attention,omitempty"` // new public egress
}

// WorkloadDrift counts one workload's new and vanished edges.
type WorkloadDrift struct {
	Namespace      string `json:"namespace,omitempty"`
	Workload       string `json:"workload"`
	New            int    `json:"new"`
	NewPublic      int    `json:"newPublic"`
	Vanished       int    `json:"vanished"`
	NewBytes       uint64 `json:"newBytes"`
	PersistentEdge int    `json:"persistent"`
}

// Report is the dependency drift answer.
type Report struct {
	Schema         string          `json:"schema"`
	Now            string          `json:"now"`
	Recent         Window          `json:"recent"`
	Baseline       Window          `json:"baseline"`
	BaselineSpan   int64           `json:"baselineSpanSeconds"` // history actually available before the recent window
	Ready          bool            `json:"ready"`
	NotReady       string          `json:"notReadyReason,omitempty"`
	Observed       int             `json:"observedDeltas"`
	Truncated      bool            `json:"truncated"`
	Persistent     int             `json:"persistentEdges"`
	NewEdges       []Edge          `json:"newEdges"`
	NewTotal       int             `json:"newTotal"`
	NewPublic      int             `json:"newPublicEgress"`
	Vanished       []Edge          `json:"vanishedEdges"`
	VanishedTotal  int             `json:"vanishedTotal"`
	Workloads      []WorkloadDrift `json:"workloads"`
	ListsTruncated bool            `json:"listsTruncated"`
	Limitations    []string        `json:"limitations"`
}

// Limitations returned with every report.
func Limitations() []string {
	return []string{
		"Built from retained flow deltas (internal/flowlog), not packets. An edge absent from the baseline may simply be older than the retained history, dropped by the row cap, or missed while an agent was down; a new edge is a lead, not a verdict.",
		"Peers are addresses as Netra recorded them. A pod that restarts with a new IP shows as a new private edge and the old one as vanished: use public_only=true to focus on external destinations, or read the name column.",
		"The baseline must be at least the minimum span of history before the recent window; with less, the report says not ready and lists nothing as new.",
		"Advisory only. Nothing here applies a deny, changes the mode or opens a capture; review a suspicious destination with deny preview before acting.",
	}
}

type edgeKey struct {
	ns, wl, dir, peer, proto string
	port                     uint16
}

type edgeAgg struct {
	e     Edge
	first time.Time
	last  time.Time
}

func workloadOf(r flowlog.Record) string {
	switch {
	case r.WorkloadName != "":
		return r.WorkloadName
	case r.Pod != "":
		return r.Pod
	}
	return "(unattributed)"
}

// PeerClass classifies a recorded peer.
func PeerClass(peer string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(peer))
	if err != nil {
		return "name"
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return "private"
	}
	return "public"
}

func aggregate(recs []flowlog.Record) (map[edgeKey]*edgeAgg, bool) {
	m := map[edgeKey]*edgeAgg{}
	capped := false
	for _, r := range recs {
		k := edgeKey{r.Namespace, workloadOf(r), strings.ToLower(r.Direction), r.Peer, strings.ToUpper(r.Protocol), r.Port}
		a := m[k]
		if a == nil {
			if len(m) >= maxEdges {
				capped = true
				continue
			}
			a = &edgeAgg{e: Edge{Namespace: k.ns, Workload: k.wl, Direction: k.dir, Peer: k.peer, PeerClass: PeerClass(k.peer), Port: k.port, Protocol: k.proto}, first: r.ObservedAt, last: r.ObservedAt}
			m[k] = a
		}
		a.e.Bytes += r.Bytes
		a.e.Packets += r.Packets
		a.e.Observations++
		if r.ObservedAt.Before(a.first) {
			a.first = r.ObservedAt
		}
		if r.ObservedAt.After(a.last) {
			a.last = r.ObservedAt
		}
		if a.e.AppProtocol == "" {
			a.e.AppProtocol = r.AppProtocol
		}
		if a.e.Name == "" {
			if r.TLSSNI != "" {
				a.e.Name = r.TLSSNI
			} else {
				a.e.Name = r.DNSName
			}
		}
	}
	return m, capped
}

func (a *edgeAgg) edge() Edge {
	e := a.e
	e.FirstSeen = a.first.UTC().Format(time.RFC3339)
	e.LastSeen = a.last.UTC().Format(time.RFC3339)
	e.Attention = e.Direction == "egress" && e.PeerClass == "public"
	return e
}

func (o *Options) normalise() {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	o.Now = o.Now.UTC()
	if o.Recent <= 0 {
		o.Recent = DefaultRecent
	}
	if o.Baseline <= 0 {
		o.Baseline = DefaultBaseline
	}
	if o.MinBaseline <= 0 {
		o.MinBaseline = DefaultMinBaseline
	}
	if o.Limit <= 0 {
		o.Limit = DefaultLimit
	}
	if o.Limit > MaxLimit {
		o.Limit = MaxLimit
	}
}

// split divides records into the baseline and recent windows and returns the
// oldest record time, which bounds the history that really exists.
func split(recs []flowlog.Record, o Options) (base, recent []flowlog.Record, oldest time.Time) {
	recentStart := o.Now.Add(-o.Recent)
	baseStart := recentStart.Add(-o.Baseline)
	for _, r := range recs {
		if r.ObservedAt.After(o.Now) || r.ObservedAt.Before(baseStart) {
			continue
		}
		if oldest.IsZero() || r.ObservedAt.Before(oldest) {
			oldest = r.ObservedAt
		}
		if r.ObservedAt.Before(recentStart) {
			base = append(base, r)
		} else {
			recent = append(recent, r)
		}
	}
	return
}

// readiness works out how much baseline history exists.
func readiness(o Options, oldest time.Time, nBase int) (span time.Duration, ready bool, why string) {
	recentStart := o.Now.Add(-o.Recent)
	if oldest.IsZero() || nBase == 0 {
		return 0, false, "no flow history before the recent window"
	}
	span = recentStart.Sub(oldest)
	if span > o.Baseline {
		span = o.Baseline
	}
	if span < o.MinBaseline {
		return span, false, fmt.Sprintf("only %s of history before the recent window, need at least %s", span.Round(time.Second), o.MinBaseline)
	}
	return span, true, ""
}

func sortEdges(l []Edge) {
	sort.Slice(l, func(i, j int) bool {
		if l[i].Attention != l[j].Attention {
			return l[i].Attention
		}
		if l[i].Bytes != l[j].Bytes {
			return l[i].Bytes > l[j].Bytes
		}
		a, b := l[i], l[j]
		return fmt.Sprint(a.Namespace, a.Workload, a.Direction, a.Peer, a.Port, a.Protocol) < fmt.Sprint(b.Namespace, b.Workload, b.Direction, b.Peer, b.Port, b.Protocol)
	})
}

// BuildDrift compares edges between the baseline and recent windows.
func BuildDrift(recs []flowlog.Record, o Options) Report {
	o.normalise()
	recentStart := o.Now.Add(-o.Recent)
	baseStart := recentStart.Add(-o.Baseline)
	base, recent, oldest := split(recs, o)
	span, ready, why := readiness(o, oldest, len(base))
	rep := Report{
		Schema: Schema, Now: o.Now.Format(time.RFC3339),
		Recent:       Window{recentStart.Format(time.RFC3339), o.Now.Format(time.RFC3339)},
		Baseline:     Window{baseStart.Format(time.RFC3339), recentStart.Format(time.RFC3339)},
		BaselineSpan: int64(span / time.Second), Ready: ready, NotReady: why,
		Observed: len(base) + len(recent), Truncated: o.Truncated,
		NewEdges: []Edge{}, Vanished: []Edge{}, Workloads: []WorkloadDrift{}, Limitations: Limitations(),
	}
	bm, c1 := aggregate(base)
	rm, c2 := aggregate(recent)
	if c1 || c2 {
		rep.Truncated = true
	}
	if !ready {
		return rep
	}
	wl := map[[2]string]*WorkloadDrift{}
	get := func(ns, w string) *WorkloadDrift {
		k := [2]string{ns, w}
		if wl[k] == nil {
			wl[k] = &WorkloadDrift{Namespace: ns, Workload: w}
		}
		return wl[k]
	}
	keep := func(e Edge) bool { return !o.PublicOnly || e.PeerClass == "public" }
	var newE, goneE []Edge
	for k, a := range rm {
		e := a.edge()
		if !keep(e) {
			continue
		}
		if _, ok := bm[k]; ok {
			rep.Persistent++
			get(k.ns, k.wl).PersistentEdge++
			continue
		}
		newE = append(newE, e)
		w := get(k.ns, k.wl)
		w.New++
		w.NewBytes += e.Bytes
		if e.Attention {
			w.NewPublic++
			rep.NewPublic++
		}
	}
	for k, a := range bm {
		if _, ok := rm[k]; ok {
			continue
		}
		e := a.edge()
		if !keep(e) || e.Observations < MinVanishedObservations {
			continue
		}
		e.Attention = false
		goneE = append(goneE, e)
		get(k.ns, k.wl).Vanished++
	}
	sortEdges(newE)
	sortEdges(goneE)
	rep.NewTotal, rep.VanishedTotal = len(newE), len(goneE)
	if len(newE) > o.Limit {
		newE, rep.ListsTruncated = newE[:o.Limit], true
	}
	if len(goneE) > o.Limit {
		goneE, rep.ListsTruncated = goneE[:o.Limit], true
	}
	if newE != nil {
		rep.NewEdges = newE
	}
	if goneE != nil {
		rep.Vanished = goneE
	}
	for _, w := range wl {
		if w.New > 0 || w.Vanished > 0 {
			rep.Workloads = append(rep.Workloads, *w)
		}
	}
	sort.Slice(rep.Workloads, func(i, j int) bool {
		a, b := rep.Workloads[i], rep.Workloads[j]
		if a.NewPublic != b.NewPublic {
			return a.NewPublic > b.NewPublic
		}
		if a.New != b.New {
			return a.New > b.New
		}
		return a.Namespace+"/"+a.Workload < b.Namespace+"/"+b.Workload
	})
	if len(rep.Workloads) > o.Limit {
		rep.Workloads, rep.ListsTruncated = rep.Workloads[:o.Limit], true
	}
	return rep
}
