// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package beacon looks for periodic egress in the retained flow history
// (internal/flowlog): one pod reaching the same peer and port at a steady
// interval, with similar byte counts, which is how command-and-control
// check-ins look and also how health checks, telemetry exporters and update
// pollers look. It reads only the records it is handed: no new collector, no
// payloads, nothing is applied or suggested as a deny.
//
// The history holds one counter delta per agent report, so timing is only
// known to a few seconds. Periods shorter than MinPeriodFloor cannot be told
// apart from a continuous connection and are never reported.
package beacon

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/flowdrift"
	"github.com/zyvorai/netra/internal/flowlog"
)

// Schema names the report.
const Schema = "netra-egress-beacons/1"

// Bounds and defaults.
const (
	DefaultWindow    = 24 * time.Hour
	MinWindow        = time.Hour
	MaxWindow        = 14 * 24 * time.Hour
	DefaultMinEvents = 10
	MinEventsFloor   = 6
	MaxMinEvents     = 10000
	DefaultMinPeriod = 30 * time.Second
	MinPeriodFloor   = 20 * time.Second
	MaxMinPeriod     = 6 * time.Hour
	DefaultMinScore  = 0.8
	MinScoreFloor    = 0.5
	DefaultLimit     = 100
	MaxLimit         = 500

	// MaxDispersion rejects a series whose interval spread (median absolute
	// deviation over median) is too wide to be called periodic, whatever its
	// other scores say. Random (Poisson) arrivals sit near 0.7.
	MaxDispersion = 0.25
	// MinCoverage rejects a series that was active for less than half of the
	// periods between its first and last event.
	MinCoverage = 0.5

	// burstGap joins deltas from consecutive agent reports into one event.
	// Agents report every 3 seconds; a transfer spanning several reports is
	// one check-in, not several.
	burstGap  = 7 * time.Second
	maxSeries = 50000
)

// Options select the window and thresholds.
type Options struct {
	Now            time.Time
	Window         time.Duration
	MinEvents      int
	MinPeriod      time.Duration
	MinScore       float64
	IncludePrivate bool
	Limit          int
	// Truncated says the record set was cut (oldest rows dropped first).
	Truncated bool
}

// Scores are the parts of a candidate's score, each from 0 to 1.
type Scores struct {
	Regularity float64 `json:"regularity"` // 1 - interval dispersion
	Symmetry   float64 `json:"symmetry"`   // 1 - |Bowley skew| of the intervals
	Size       float64 `json:"size"`       // 1 - byte dispersion per event
	Coverage   float64 `json:"coverage"`   // events seen over events expected between first and last
}

// Candidate is one periodic pod-to-peer series.
type Candidate struct {
	Namespace     string  `json:"namespace,omitempty"`
	Workload      string  `json:"workload"`
	Pod           string  `json:"pod,omitempty"`
	Node          string  `json:"node,omitempty"`
	Peer          string  `json:"peer"`
	PeerClass     string  `json:"peerClass"`
	Port          uint16  `json:"port"`
	Protocol      string  `json:"protocol,omitempty"`
	Name          string  `json:"name,omitempty"` // DNS name or SNI joined by the agent, when seen
	Comm          string  `json:"comm,omitempty"` // process name joined from TCP health, when seen
	Events        int     `json:"events"`
	PeriodSeconds float64 `json:"periodSeconds"` // median interval between events
	JitterSeconds float64 `json:"jitterSeconds"` // median absolute deviation of the intervals
	Dispersion    float64 `json:"dispersion"`    // jitter over period
	Score         float64 `json:"score"`
	Scores        Scores  `json:"scores"`
	MedianBytes   uint64  `json:"medianBytes"`
	TotalBytes    uint64  `json:"totalBytes"`
	FirstSeen     string  `json:"firstSeen"`
	LastSeen      string  `json:"lastSeen"`
	// Hint names a well-known periodic protocol seen on this port. It lowers
	// the row in the list; it does not prove what the traffic is.
	Hint string `json:"hint,omitempty"`
}

// Report is the answer to GET /api/v1/security/beacons.
type Report struct {
	Schema      string `json:"schema"`
	Now         string `json:"now"`
	Start       string `json:"start"`
	HistorySpan int64  `json:"historySpanSeconds"` // history actually available inside the window
	Ready       bool   `json:"ready"`
	NotReady    string `json:"notReadyReason,omitempty"`

	MinEvents        int     `json:"minEvents"`
	MinPeriodSeconds float64 `json:"minPeriodSeconds"`
	MinScore         float64 `json:"minScore"`
	IncludePrivate   bool    `json:"includePrivate"`

	Observed      int         `json:"observedDeltas"` // egress deltas considered
	Series        int         `json:"series"`         // pod-to-peer series considered
	TooFew        int         `json:"seriesTooFewEvents"`
	Truncated     bool        `json:"truncated"`
	Candidates    []Candidate `json:"candidates"`
	Total         int         `json:"total"`
	ListTruncated bool        `json:"listTruncated"`
	Limitations   []string    `json:"limitations"`
}

// Limitations returned with every report.
func Limitations() []string {
	return []string{
		"Periodic is not malicious: health checks, telemetry and metrics exporters, license and update pollers and cron jobs all look like this. A candidate is a lead to identify, never a verdict.",
		"Built from retained flow deltas that arrive once per agent report (about 3 seconds), so periods under 20 seconds, and one long-lived connection that keeps sending, cannot be seen as separate events.",
		"A beacon that randomises its interval widely, changes address on each check-in, or runs less often than the window can hold is not reported. An empty list is not proof that there is none.",
		"Advisory only: nothing is applied, blocked or captured. Review a destination with deny preview before acting.",
	}
}

func (o *Options) normalise() {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	o.Now = o.Now.UTC()
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	if o.MinEvents < MinEventsFloor || o.MinEvents > MaxMinEvents {
		o.MinEvents = DefaultMinEvents
	}
	if o.MinPeriod < MinPeriodFloor || o.MinPeriod > MaxMinPeriod {
		o.MinPeriod = DefaultMinPeriod
	}
	if o.MinScore < MinScoreFloor || o.MinScore > 1 {
		o.MinScore = DefaultMinScore
	}
	if o.Limit <= 0 {
		o.Limit = DefaultLimit
	}
	if o.Limit > MaxLimit {
		o.Limit = MaxLimit
	}
}

type seriesKey struct {
	node, ns, wl, pod, peer, proto string
	port                           uint16
}

type sample struct {
	at    time.Time
	bytes uint64
}

type series struct {
	samples    []sample
	name, comm string
}

// Build finds periodic egress series in recs.
func Build(recs []flowlog.Record, o Options) Report {
	o.normalise()
	start := o.Now.Add(-o.Window)
	rep := Report{
		Schema: Schema, Now: o.Now.Format(time.RFC3339), Start: start.Format(time.RFC3339),
		MinEvents: o.MinEvents, MinPeriodSeconds: o.MinPeriod.Seconds(), MinScore: o.MinScore,
		IncludePrivate: o.IncludePrivate, Truncated: o.Truncated,
		Candidates: []Candidate{}, Limitations: Limitations(),
	}

	var oldest time.Time
	m := map[seriesKey]*series{}
	for _, r := range recs {
		if r.ObservedAt.After(o.Now) || r.ObservedAt.Before(start) {
			continue
		}
		if oldest.IsZero() || r.ObservedAt.Before(oldest) {
			oldest = r.ObservedAt
		}
		// A delta with no packets and no bytes (a retransmit counter moving,
		// say) is not a send.
		if !strings.EqualFold(r.Direction, "egress") || (r.Packets == 0 && r.Bytes == 0) {
			continue
		}
		if !o.IncludePrivate && flowdrift.PeerClass(r.Peer) == "private" {
			continue
		}
		rep.Observed++
		wl := r.WorkloadName
		if wl == "" {
			wl = r.Pod
		}
		if wl == "" {
			wl = "(unattributed)"
		}
		k := seriesKey{r.Node, r.Namespace, wl, r.Pod, r.Peer, strings.ToUpper(r.Protocol), r.Port}
		s := m[k]
		if s == nil {
			if len(m) >= maxSeries {
				rep.Truncated = true
				continue
			}
			s = &series{}
			m[k] = s
		}
		s.samples = append(s.samples, sample{r.ObservedAt, r.Bytes})
		if s.name == "" {
			if r.TLSSNI != "" {
				s.name = r.TLSSNI
			} else {
				s.name = r.DNSName
			}
		}
		if s.comm == "" {
			s.comm = r.Comm
		}
	}

	need := time.Duration(o.MinEvents-1) * o.MinPeriod
	var span time.Duration
	if !oldest.IsZero() {
		span = o.Now.Sub(oldest)
	}
	rep.HistorySpan = int64(span / time.Second)
	if oldest.IsZero() || span < need {
		rep.NotReady = fmt.Sprintf("flow history inside the window spans %s; %d events at least %s apart need %s", span.Round(time.Second), o.MinEvents, o.MinPeriod, need)
		return rep
	}
	rep.Ready = true
	rep.Series = len(m)

	for k, s := range m {
		c, enough, ok := evaluate(s, o)
		if !enough {
			rep.TooFew++
			continue
		}
		if !ok {
			continue
		}
		c.Node, c.Namespace, c.Workload, c.Pod = k.node, k.ns, k.wl, k.pod
		c.Peer, c.PeerClass, c.Port, c.Protocol = k.peer, flowdrift.PeerClass(k.peer), k.port, k.proto
		c.Name, c.Comm = s.name, s.comm
		c.Hint = hint(k.port, k.proto)
		rep.Candidates = append(rep.Candidates, c)
	}
	sort.Slice(rep.Candidates, func(i, j int) bool { return less(rep.Candidates[i], rep.Candidates[j]) })
	rep.Total = len(rep.Candidates)
	if len(rep.Candidates) > o.Limit {
		rep.Candidates, rep.ListTruncated = rep.Candidates[:o.Limit], true
	}
	return rep
}

// less orders unexplained candidates first, public peers before others, then
// by score and event count, with a stable key as the last resort.
func less(a, b Candidate) bool {
	if (a.Hint == "") != (b.Hint == "") {
		return a.Hint == ""
	}
	if (a.PeerClass == "public") != (b.PeerClass == "public") {
		return a.PeerClass == "public"
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if a.Events != b.Events {
		return a.Events > b.Events
	}
	return fmt.Sprint(a.Namespace, "|", a.Workload, "|", a.Pod, "|", a.Node, "|", a.Peer, "|", a.Port, "|", a.Protocol) <
		fmt.Sprint(b.Namespace, "|", b.Workload, "|", b.Pod, "|", b.Node, "|", b.Peer, "|", b.Port, "|", b.Protocol)
}

// bursts joins samples less than burstGap apart into one event, which keeps
// the first sample's time and the summed bytes.
func bursts(in []sample) []sample {
	sort.Slice(in, func(i, j int) bool { return in[i].at.Before(in[j].at) })
	var out []sample
	var last time.Time
	for _, s := range in {
		if len(out) == 0 || s.at.Sub(last) > burstGap {
			out = append(out, s)
		} else {
			out[len(out)-1].bytes += s.bytes
		}
		last = s.at
	}
	return out
}

// evaluate scores one series. enough is false when there are too few events to
// judge; ok is true when the series passes every threshold.
func evaluate(s *series, o Options) (c Candidate, enough, ok bool) {
	ev := bursts(s.samples)
	if len(ev) < o.MinEvents {
		return c, false, false
	}
	iv := make([]float64, 0, len(ev)-1)
	sizes := make([]float64, 0, len(ev))
	var total uint64
	for i, e := range ev {
		if i > 0 {
			iv = append(iv, e.at.Sub(ev[i-1].at).Seconds())
		}
		sizes = append(sizes, float64(e.bytes))
		total += e.bytes
	}
	sort.Float64s(iv)
	sort.Float64s(sizes)
	period := quantile(iv, 0.5)
	if period < o.MinPeriod.Seconds() {
		return c, true, false
	}
	jitter := mad(iv, period)
	dispersion := jitter / period

	// Bowley skew is meaningless when the spread is only sampling noise.
	q1, q3 := quantile(iv, 0.25), quantile(iv, 0.75)
	skew := 0.0
	if iqr := q3 - q1; iqr >= math.Max(10, period*0.1) {
		skew = (q1 + q3 - 2*period) / iqr
	}
	med := quantile(sizes, 0.5)
	size := 0.0
	if med > 0 {
		size = clamp01(1 - mad(sizes, med)/med)
	}
	first, last := ev[0].at, ev[len(ev)-1].at
	coverage := clamp01(float64(len(ev)) / (last.Sub(first).Seconds()/period + 1))
	sc := Scores{Regularity: clamp01(1 - dispersion), Symmetry: clamp01(1 - math.Abs(skew)), Size: size, Coverage: coverage}
	score := 0.4*sc.Regularity + 0.1*sc.Symmetry + 0.2*sc.Size + 0.3*sc.Coverage
	if dispersion > MaxDispersion || coverage < MinCoverage || round3(score) < o.MinScore {
		return c, true, false
	}
	return Candidate{
		Events: len(ev), PeriodSeconds: round3(period), JitterSeconds: round3(jitter), Dispersion: round3(dispersion),
		Score: round3(score), Scores: Scores{round3(sc.Regularity), round3(sc.Symmetry), round3(sc.Size), round3(sc.Coverage)},
		MedianBytes: uint64(med), TotalBytes: total,
		FirstSeen: first.UTC().Format(time.RFC3339), LastSeen: last.UTC().Format(time.RFC3339),
	}, true, true
}

// quantile interpolates linearly on a sorted, non-empty slice.
func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	pos := q * float64(len(sorted)-1)
	lo := int(pos)
	if lo+1 >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	return sorted[lo] + (pos-float64(lo))*(sorted[lo+1]-sorted[lo])
}

// mad is the median absolute deviation around center.
func mad(v []float64, center float64) float64 {
	d := make([]float64, len(v))
	for i, x := range v {
		d[i] = math.Abs(x - center)
	}
	sort.Float64s(d)
	return quantile(d, 0.5)
}

func hint(port uint16, proto string) string {
	switch {
	case port == 123 && proto == "UDP":
		return "network time (port 123)"
	case port == 53:
		return "DNS (port 53)"
	}
	return ""
}

func clamp01(f float64) float64 { return math.Max(0, math.Min(1, f)) }

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
