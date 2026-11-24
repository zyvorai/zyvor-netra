// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReportSchema identifies the offline incident report.
const ReportSchema = "netra-incident-report/1"

// Report bounds.
const (
	ReportLead      = 15 * time.Minute // how far before the first break a change counts as a precursor
	ReportMaxLead   = 10
	ReportMaxEvents = 40
	ReportMaxPeaks  = 12
)

// Report is a deterministic, offline post-incident draft derived from a
// verified bundle. It adds no data: every line points back at a bundle row.
// Ordering is temporal, never causal: a precursor is a change that happened
// shortly before the first break, not a proven cause.
type Report struct {
	Schema      string        `json:"schema"`
	BundleHead  string        `json:"bundleHead"`
	Window      Window        `json:"window"`
	Scope       string        `json:"scope"`
	Node        string        `json:"node,omitempty"`
	Version     string        `json:"version"`
	Mode        string        `json:"mode"`
	Verdict     string        `json:"verdict"` // quiet | changes-only | breaks
	FirstBreak  *ReportEvent  `json:"firstBreak,omitempty"`
	Precursors  []ReportEvent `json:"precursors"`
	Events      []ReportEvent `json:"events"`
	EventsTotal int           `json:"eventsTotal"`
	Peaks       []ReportPeak  `json:"peaks"`
	Deny        ReportDeny    `json:"deny"`
	UndatedWarn int           `json:"undatedWarnings"`
	Confidence  []string      `json:"confidence"`
	Caveats     []string      `json:"caveats"`
}

// ReportEvent is one timeline row plus its distance from the first break.
type ReportEvent struct {
	At          string `json:"at"`
	Category    string `json:"category"`
	Class       string `json:"class"`
	Severity    string `json:"severity"`
	Node        string `json:"node,omitempty"`
	Summary     string `json:"summary"`
	Ref         string `json:"ref"`
	SecondsPrev int64  `json:"secondsBeforeFirstBreak,omitempty"`
}

// ReportPeak is one key signal's range over the window.
type ReportPeak struct {
	Context string   `json:"context"`
	Scope   string   `json:"scope"`
	Units   string   `json:"units,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Avg     *float64 `json:"avg,omitempty"`
	Max     *float64 `json:"max,omitempty"`
}

// ReportDeny summarises deny lease activity in the window.
type ReportDeny struct {
	Mode       string         `json:"mode"`
	LiveLeases int            `json:"liveLeases"`
	Changes    map[string]int `json:"changes"`
	BreakGlass int            `json:"breakGlass"`
}

// BuildReport verifies data and derives the report. A bundle that does not
// verify produces an error, never a report.
func BuildReport(data []byte) (*Report, error) {
	doc, err := loadVerified(data)
	if err != nil {
		return nil, err
	}
	var (
		nodes NodesSection
		met   MetricsSection
		ebpf  EBPFSection
		tl    TimelineSection
	)
	for name, dst := range map[string]any{SecNodes: &nodes, SecMetrics: &met, SecEBPF: &ebpf, SecTimeline: &tl} {
		if raw, ok := doc.Sections[name]; ok {
			if err := json.Unmarshal(raw, dst); err != nil {
				return nil, fmt.Errorf("section %s: %w", name, err)
			}
		}
	}
	r := &Report{
		Schema: ReportSchema, BundleHead: doc.Integrity.Head, Window: doc.Window, Scope: doc.Identity.Scope,
		Node: doc.Identity.Node, Version: doc.Identity.Version, Mode: doc.Identity.Mode,
		Precursors: []ReportEvent{}, Events: []ReportEvent{}, Peaks: []ReportPeak{}, Confidence: []string{},
		Caveats: append([]string{}, doc.Caveats...),
	}

	type dated struct {
		t time.Time
		e ReportEvent
	}
	var all []dated
	for _, e := range tl.Entries {
		if !e.AtKnown {
			if e.Severity == "warning" || e.Severity == "critical" {
				r.UndatedWarn++
			}
			continue
		}
		t, err := time.Parse(time.RFC3339, e.At)
		if err != nil {
			continue
		}
		all = append(all, dated{t, ReportEvent{At: e.At, Category: e.Category, Class: e.Class, Severity: e.Severity, Node: e.Node, Summary: e.Summary, Ref: e.Ref}})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })

	firstBreak := -1
	for i, d := range all {
		if d.e.Class == "break" {
			firstBreak = i
			break
		}
	}
	hasChange := false
	for _, d := range all {
		if d.e.Class == "change" {
			hasChange = true
			break
		}
	}
	switch {
	case firstBreak >= 0:
		r.Verdict = "breaks"
		fb := all[firstBreak].e
		r.FirstBreak = &fb
		// Nearest changes first, so the likeliest precursor leads.
		for i := firstBreak - 1; i >= 0 && len(r.Precursors) < ReportMaxLead; i-- {
			d := all[i]
			gap := all[firstBreak].t.Sub(d.t)
			if gap > ReportLead {
				break
			}
			if d.e.Class == "change" {
				ev := d.e
				ev.SecondsPrev = int64(gap / time.Second)
				r.Precursors = append(r.Precursors, ev)
			}
		}
	case hasChange:
		r.Verdict = "changes-only"
	default:
		r.Verdict = "quiet"
	}

	for _, d := range all {
		if d.e.Class == "change" || d.e.Class == "break" {
			r.EventsTotal++
			if len(r.Events) < ReportMaxEvents {
				r.Events = append(r.Events, d.e)
			}
		}
	}

	for _, s := range met.Series {
		if s.Max == nil {
			continue
		}
		r.Peaks = append(r.Peaks, ReportPeak{Context: s.Context, Scope: s.Scope, Units: s.Units, Min: s.Min, Avg: s.Avg, Max: s.Max})
	}
	sort.SliceStable(r.Peaks, func(i, j int) bool {
		if r.Peaks[i].Context != r.Peaks[j].Context {
			return r.Peaks[i].Context < r.Peaks[j].Context
		}
		return r.Peaks[i].Scope < r.Peaks[j].Scope
	})
	if len(r.Peaks) > ReportMaxPeaks {
		r.Peaks = r.Peaks[:ReportMaxPeaks]
	}

	r.Deny = ReportDeny{Mode: ebpf.Deny.Mode, LiveLeases: len(ebpf.Leases), Changes: map[string]int{}}
	for _, c := range ebpf.LeaseChanges {
		r.Deny.Changes[c.Action]++
		if c.BreakGlass {
			r.Deny.BreakGlass++
		}
	}

	// Confidence: what the reader must not over-trust.
	for _, g := range nodes.Gaps {
		r.Confidence = append(r.Confidence, "blind spot: "+g)
	}
	for _, name := range SectionNames {
		raw, ok := doc.Sections[name]
		if !ok {
			continue
		}
		var m Meta
		_ = json.Unmarshal(raw, &m)
		if m.Excluded {
			r.Confidence = append(r.Confidence, "section "+name+" was excluded from the bundle")
		} else if !m.Available {
			r.Confidence = append(r.Confidence, "section "+name+" had no data source"+noteSuffix(m.Note))
		}
		for _, t := range m.Truncated {
			r.Confidence = append(r.Confidence, fmt.Sprintf("section %s list %s was cut to %d of %d rows", name, t.List, t.Kept, t.Total))
		}
	}
	if r.Verdict == "quiet" && len(r.Confidence) > 0 {
		r.Confidence = append(r.Confidence, "a quiet timeline with blind spots is not evidence that nothing happened")
	}
	if r.UndatedWarn > 0 {
		r.Confidence = append(r.Confidence, fmt.Sprintf("%d warning or critical findings carry no event time (current state, not history)", r.UndatedWarn))
	}
	return r, nil
}

func noteSuffix(n string) string {
	if n == "" {
		return ""
	}
	return " (" + n + ")"
}

func fnum(p *float64) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf("%.4g", *p)
}

// Markdown renders the report. Output is deterministic for a given bundle.
func (r *Report) Markdown() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("# Incident report draft\n\n")
	scope := r.Scope
	if r.Node != "" {
		scope += " " + r.Node
	}
	w("- Window: %s to %s (%d min)\n- Scope: %s, mode %s, Netra %s\n- Bundle chain head: `%s`\n- Verdict: **%s**\n\n", r.Window.Start, r.Window.End, r.Window.Minutes, scope, r.Mode, r.Version, r.BundleHead, r.Verdict)
	w("## What broke first\n\n")
	if r.FirstBreak == nil {
		w("No break-class event with a known time in this window.\n\n")
	} else {
		f := r.FirstBreak
		w("%s  %s  %s%s: %s  (`%s`)\n\n", f.At, f.Severity, f.Category, nodeSuffix(f.Node), f.Summary, f.Ref)
		w("## Changes shortly before it\n\nTemporal order only, not proof of cause.\n\n")
		if len(r.Precursors) == 0 {
			w("None recorded within %d minutes before it.\n\n", int(ReportLead/time.Minute))
		}
		for _, p := range r.Precursors {
			w("- %ds before: %s  %s%s: %s  (`%s`)\n", p.SecondsPrev, p.At, p.Category, nodeSuffix(p.Node), p.Summary, p.Ref)
		}
		if len(r.Precursors) > 0 {
			w("\n")
		}
	}
	w("## Timeline of changes and breaks\n\n")
	if len(r.Events) == 0 {
		w("None.\n\n")
	}
	for _, e := range r.Events {
		w("- %s  %s  %s/%s%s: %s  (`%s`)\n", e.At, e.Severity, e.Class, e.Category, nodeSuffix(e.Node), e.Summary, e.Ref)
	}
	if r.EventsTotal > len(r.Events) {
		w("- ... %d more in the bundle timeline\n", r.EventsTotal-len(r.Events))
	}
	w("\n## Key signals\n\n")
	if len(r.Peaks) == 0 {
		w("No metric series in the bundle.\n\n")
	} else {
		w("| signal | scope | min | avg | max | units |\n|---|---|---|---|---|---|\n")
		for _, p := range r.Peaks {
			w("| %s | %s | %s | %s | %s | %s |\n", p.Context, p.Scope, fnum(p.Min), fnum(p.Avg), fnum(p.Max), p.Units)
		}
		w("\n")
	}
	w("## Deny activity\n\nMode %s, %d live leases", r.Deny.Mode, r.Deny.LiveLeases)
	keys := make([]string, 0, len(r.Deny.Changes))
	for k := range r.Deny.Changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w(", %d %s", r.Deny.Changes[k], k)
	}
	if r.Deny.BreakGlass > 0 {
		w(", %d break-glass", r.Deny.BreakGlass)
	}
	w(".\n\n## How far to trust this\n\n")
	if len(r.Confidence) == 0 {
		w("No blind spots or cuts recorded.\n")
	}
	for _, c := range r.Confidence {
		w("- %s\n", c)
	}
	if len(r.Caveats) > 0 {
		w("\n## Bundle caveats\n\n")
		for _, c := range r.Caveats {
			w("- %s\n", c)
		}
	}
	return b.String()
}

func nodeSuffix(n string) string {
	if n == "" {
		return ""
	}
	return " [" + n + "]"
}
