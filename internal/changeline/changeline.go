// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package changeline joins what Netra already records about change (the audit
// log, the netlink change recorder, the BPF attachment inventory) with what
// broke (drop attribution, metric anomaly bursts, metric alert transitions)
// into one ordered "what changed, then what broke" timeline.
//
// Pure and observe-only: it takes already-computed results, reads nothing and
// changes nothing. It never mutates a route, program, rule or alert. A
// "suspect" is a change that preceded a break on the same node; it is a lead
// for the operator, not a proven cause, and every Result says so.
package changeline

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/timeline"
)

// Entry classes.
const (
	ClassChange  = "change"  // something was altered
	ClassBreak   = "break"   // something got worse
	ClassContext = "context" // recovery or other context
)

// Sources.
const (
	SourceAudit     = "audit"
	SourceNetlink   = "netlink"
	SourceBPFAttach = "bpf-attach"
	SourceDrops     = "drops"
	SourceAnomaly   = "metric-anomaly"
	SourceAlert     = "metric-alert"
)

// Caveat is fixed on every Result.
const Caveat = "Ordering shows what preceded what, not what caused what. A suspect is a recorded change on the same node (or cluster-wide) shortly before a break. Drop and attachment findings are level-triggered counters with no event time, so they are listed as current state and never paired as suspects. Missing sources or history gaps are listed under gaps; an empty suspect list with gaps is not a clean bill of health."

const (
	maxEntries      = 2000
	maxSuspectsPer  = 5
	defaultLead     = 10 * time.Minute
	maxLead         = 6 * time.Hour
	anomalyBurstMin = 20.0 // percent of samples anomalous in a bucket
)

// Entry is one ordered point.
type Entry struct {
	At       time.Time `json:"at,omitzero"`
	AtKnown  bool      `json:"atKnown"`
	Class    string    `json:"class"`
	Source   string    `json:"source"`
	Node     string    `json:"node,omitempty"`
	Severity string    `json:"severity,omitempty"` // info|warning|critical
	Summary  string    `json:"summary"`
}

// Suspect pairs a break with the changes that preceded it.
type Suspect struct {
	Break   Entry   `json:"break"`
	Changes []Entry `json:"changes"`
	// SameNode is true when the first change is on the break's node.
	SameNode bool `json:"sameNode"`
}

// Result is the timeline.
type Result struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	Since       time.Time      `json:"since"`
	Lead        string         `json:"lead"`
	Entries     []Entry        `json:"entries"`
	Suspects    []Suspect      `json:"suspects"`
	Gaps        []string       `json:"gaps"`
	Counts      map[string]int `json:"counts"`
	Truncated   bool           `json:"truncated,omitempty"`
	Caveat      string         `json:"caveat"`
}

// AnomalyPoint is a node's anomaly rate (percent) in one bucket.
type AnomalyPoint struct {
	Node string
	At   time.Time
	Rate float64
}

// AlertChange is one metric-alert status transition.
type AlertChange struct {
	At       time.Time
	Rule     string
	Node     string
	From, To string // clear|warning|critical|...
	Info     string
	Silenced bool
}

// Inputs are the already-computed signals. Zero values are fine: an absent
// source just contributes nothing (the caller reports it through Gaps).
type Inputs struct {
	Now     time.Time
	Since   time.Time
	Lead    time.Duration
	Node    string // when set, entries from other nodes are dropped
	Audit   []models.AuditEvent
	Netlink []models.NetlinkEvent
	Attach  []models.BPFAttachFinding
	Drops   []models.DropDetectiveFinding
	Anomaly []AnomalyPoint
	Alerts  []AlertChange
	Gaps    []string
}

// ClampLead bounds an operator-supplied lead window.
func ClampLead(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultLead
	}
	if d > maxLead {
		return maxLead
	}
	return d
}

// Build is deterministic for fixed inputs.
func Build(in Inputs) Result {
	lead := ClampLead(in.Lead)
	res := Result{
		GeneratedAt: in.Now.UTC(), Since: in.Since.UTC(), Lead: lead.String(),
		Entries: []Entry{}, Suspects: []Suspect{}, Gaps: append([]string{}, in.Gaps...),
		Counts: map[string]int{}, Caveat: Caveat,
	}
	var es []Entry
	keepNode := func(n string) bool { return in.Node == "" || n == "" || n == in.Node }
	inWindow := func(t time.Time) bool {
		return !t.IsZero() && !t.Before(in.Since) && (in.Now.IsZero() || !t.After(in.Now.Add(time.Minute)))
	}

	for _, a := range in.Audit {
		if !inWindow(a.At) {
			continue
		}
		es = append(es, Entry{At: a.At.UTC(), AtKnown: true, Class: ClassChange, Source: SourceAudit, Severity: "info", Summary: clip(timeline.ExplainAuditEvent(a))})
	}
	for _, e := range in.Netlink {
		if !inWindow(e.ObservedAt) || !keepNode(e.Node) {
			continue
		}
		if e.Kind == models.NetlinkKindOverrun {
			res.Gaps = append(res.Gaps, fmt.Sprintf("netlink recorder overrun on %s at %s: changes right around then may be missing", orUnknown(e.Node), e.ObservedAt.UTC().Format(time.RFC3339)))
			continue
		}
		es = append(es, netlinkEntry(e))
	}
	for _, f := range in.Attach {
		if !keepNode(f.Node) {
			continue
		}
		es = append(es, Entry{Class: ClassBreak, Source: SourceBPFAttach, Node: f.Node, Severity: normSev(f.Severity), Summary: clip(fmt.Sprintf("BPF attachment %s on %s: %s", f.Kind, f.Subject, f.Message))})
	}
	for _, d := range in.Drops {
		if !keepNode(d.Node) {
			continue
		}
		es = append(es, Entry{Class: ClassBreak, Source: SourceDrops, Node: d.Node, Severity: dropSev(d), Summary: clip(fmt.Sprintf("%d packets dropped (%s): %s", d.Packets, d.Code, d.Explanation))})
	}
	es = append(es, anomalyBursts(in, keepNode, inWindow)...)
	for _, a := range in.Alerts {
		if !inWindow(a.At) || !keepNode(a.Node) {
			continue
		}
		raised := a.To == "warning" || a.To == "critical"
		cls, sev := ClassContext, "info"
		verb := "changed to " + a.To
		if raised {
			cls, sev = ClassBreak, a.To
			verb = "raised to " + a.To
		} else if a.To == "clear" {
			verb = "cleared"
		}
		s := fmt.Sprintf("metric alert %s on %s %s", a.Rule, orUnknown(a.Node), verb)
		if a.Info != "" {
			s += ": " + a.Info
		}
		if a.Silenced {
			s += " (notifications silenced)"
		}
		es = append(es, Entry{At: a.At.UTC(), AtKnown: true, Class: cls, Source: SourceAlert, Node: a.Node, Severity: sev, Summary: clip(s)})
	}

	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.AtKnown != b.AtKnown {
			return a.AtKnown // timed entries first; level-triggered state last
		}
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Summary < b.Summary
	})
	if len(es) > maxEntries {
		// keep the newest timed entries and every untimed one
		drop := len(es) - maxEntries
		kept := es[:0:0]
		for _, e := range es {
			if drop > 0 && e.AtKnown {
				drop--
				continue
			}
			kept = append(kept, e)
		}
		es = kept
		res.Truncated = true
	}
	for _, e := range es {
		res.Counts[e.Class]++
	}
	if es == nil {
		es = []Entry{}
	}
	res.Entries = es
	res.Suspects = suspects(es, lead)
	sort.Strings(res.Gaps)
	res.Gaps = dedupe(res.Gaps)
	return res
}

func suspects(es []Entry, lead time.Duration) []Suspect {
	out := []Suspect{}
	for bi, b := range es {
		if b.Class != ClassBreak || !b.AtKnown {
			continue
		}
		var same, other []Entry
		for ci := bi - 1; ci >= 0; ci-- {
			c := es[ci]
			if c.Class != ClassChange || !c.AtKnown {
				continue
			}
			if b.At.Sub(c.At) > lead {
				break
			}
			switch {
			case c.Node != "" && c.Node == b.Node:
				same = append(same, c)
			case c.Node == "" || b.Node == "":
				other = append(other, c) // cluster-wide (audit) or unattributed
			}
		}
		// nearest first within each tier; same-node changes outrank cluster-wide ones
		cs := append(same, other...)
		if len(cs) == 0 {
			continue
		}
		if len(cs) > maxSuspectsPer {
			cs = cs[:maxSuspectsPer]
		}
		out = append(out, Suspect{Break: b, Changes: cs, SameNode: len(same) > 0})
	}
	return out
}

func anomalyBursts(in Inputs, keepNode func(string) bool, inWindow func(time.Time) bool) []Entry {
	byNode := map[string][]AnomalyPoint{}
	for _, p := range in.Anomaly {
		if keepNode(p.Node) && inWindow(p.At) && p.Rate >= anomalyBurstMin {
			byNode[p.Node] = append(byNode[p.Node], p)
		}
	}
	nodes := make([]string, 0, len(byNode))
	for n := range byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	var out []Entry
	for _, n := range nodes {
		ps := byNode[n]
		sort.Slice(ps, func(i, j int) bool { return ps[i].At.Before(ps[j].At) })
		// Merge buckets within 2 minutes of each other into one burst.
		start, last, peak := ps[0].At, ps[0].At, ps[0].Rate
		flush := func() {
			sev := "warning"
			if peak >= 50 {
				sev = "critical"
			}
			out = append(out, Entry{At: start.UTC(), AtKnown: true, Class: ClassBreak, Source: SourceAnomaly, Node: n, Severity: sev,
				Summary: fmt.Sprintf("metric anomaly burst on %s, peak %.0f%% of samples anomalous, lasting %s", orUnknown(n), peak, last.Sub(start).Round(time.Second))})
		}
		for _, p := range ps[1:] {
			if p.At.Sub(last) > 2*time.Minute {
				flush()
				start, peak = p.At, 0
			}
			last = p.At
			peak = max(peak, p.Rate)
		}
		flush()
	}
	return out
}

func netlinkEntry(e models.NetlinkEvent) Entry {
	subj := e.Kind
	switch {
	case e.Interface != "" && e.Destination != "":
		subj = fmt.Sprintf("%s %s via %s", e.Kind, e.Destination, e.Interface)
	case e.Interface != "":
		subj = fmt.Sprintf("%s %s", e.Kind, e.Interface)
	case e.Destination != "":
		subj = fmt.Sprintf("%s %s", e.Kind, e.Destination)
	case e.Address != "":
		subj = fmt.Sprintf("%s %s", e.Kind, e.Address)
	}
	s := fmt.Sprintf("netlink: %s %s", subj, e.Action)
	if e.Actor != nil && e.Actor.Comm != "" {
		s += fmt.Sprintf(" by %s (pid %d, %s)", e.Actor.Comm, e.Actor.PID, e.Actor.Confidence)
	} else if e.Origin == models.NetlinkOriginKernel {
		s += " by the kernel"
	}
	sev := "info"
	if e.Action == "delete" && (e.Kind == models.NetlinkKindLink || e.Kind == models.NetlinkKindRoute) {
		sev = "warning"
	}
	return Entry{At: e.ObservedAt.UTC(), AtKnown: true, Class: ClassChange, Source: SourceNetlink, Node: e.Node, Severity: sev, Summary: clip(s)}
}

func dropSev(d models.DropDetectiveFinding) string {
	if strings.EqualFold(d.Confidence, "high") && d.Packets >= 1000 {
		return "warning"
	}
	return "info"
}

func normSev(s string) string {
	switch s {
	case "critical", "warning", "info":
		return s
	}
	return "info"
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown node"
	}
	return s
}

// clip bounds a summary: strings come from agents and operators.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
