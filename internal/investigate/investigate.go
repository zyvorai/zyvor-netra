// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package investigate composes observe surfaces into an evidence-backed
// failed-connection timeline. It never mutates mode, rules or policy.
package investigate

import (
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
)

// Request scopes one failed-connection investigation.
type Request struct {
	Namespace string    `json:"namespace,omitempty"`
	Pod       string    `json:"pod,omitempty"`
	Peer      string    `json:"peer,omitempty"`
	Port      uint16    `json:"port,omitempty"`
	Node      string    `json:"node,omitempty"`
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
}

// Event is one evidence point on the timeline.
type Event struct {
	TS         time.Time `json:"ts"`
	Source     string    `json:"source"`
	Stage      string    `json:"stage"`
	Summary    string    `json:"summary"`
	Confidence string    `json:"confidence"` // high|medium|low|none
	Link       string    `json:"link,omitempty"`
}

// Gap explains where visibility ends for a stage.
type Gap struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
	Link   string `json:"link,omitempty"`
}

// Confidence is an operator-facing scorecard of data quality.
type Confidence struct {
	Overall            string   `json:"overall"` // high|medium|low
	SensorAvailability []string `json:"sensorAvailability,omitempty"`
	SamplingLoss       []string `json:"samplingLoss,omitempty"`
	StaleAttribution   []string `json:"staleAttribution,omitempty"`
	RetentionGaps      []string `json:"retentionGaps,omitempty"`
	Notes              []string `json:"notes,omitempty"`
}

// Result is POST /api/v1/investigate/connection.
type Result struct {
	Request     Request    `json:"request"`
	Events      []Event    `json:"events"`
	Gaps        []Gap      `json:"gaps,omitempty"`
	Confidence  Confidence `json:"confidence"`
	Limitations []string   `json:"limitations"`
}

// Input is pre-fetched observe data. Handlers fill this; Compose stays pure.
type Input struct {
	Now             time.Time
	Agents          []models.AgentStatus
	FlowRecords     []flowlog.Record
	FlowLimitations []string
	Coverage        coverage.Matrix
	Captures        []models.CaptureHistoryEntry
	DNSRows         []DNSRow
	Detective       []DetectiveHit
	PathNotes       []string
	DropNotes       []string
	NetlinkEvents   []models.NetlinkEvent
}

// DNSRow is a minimal DNS board row for the timeline.
type DNSRow struct {
	Name     string
	Failures uint64
	Queries  uint64
}

// DetectiveHit is a minimal drop/policy finding.
type DetectiveHit struct {
	Summary    string
	Confidence string
	Namespace  string
	Pod        string
	Peer       string
}

// Compose builds the timeline and confidence scorecard.
func Compose(req Request, in Input) Result {
	if req.Until.IsZero() {
		req.Until = in.Now
	}
	if req.Since.IsZero() {
		req.Since = req.Until.Add(-15 * time.Minute)
	}
	res := Result{
		Request: req,
		Events:  []Event{},
		Gaps:    []Gap{},
		Limitations: []string{
			"Timeline composes existing observe APIs; it does not decrypt traffic or invent missing sensors.",
			"Policy explain uses current config plus cumulative counters, not the winning rule ID at time T.",
			"Inferred relationships are labeled; absence of an event is a visibility gap, not proof of success.",
		},
	}
	if len(in.FlowLimitations) > 0 {
		res.Limitations = append(res.Limitations, in.FlowLimitations...)
	}

	stagesSeen := map[string]bool{}

	// DNS
	for _, d := range in.DNSRows {
		if d.Failures == 0 {
			continue
		}
		if req.Peer != "" && !strings.Contains(d.Name, req.Peer) && !strings.Contains(req.Peer, d.Name) {
			continue
		}
		res.Events = append(res.Events, Event{
			TS: req.Until, Source: "dns", Stage: "dns",
			Summary:    "DNS failures for " + d.Name + " (" + u64(d.Failures) + "/" + u64(d.Queries) + ")",
			Confidence: "medium",
			Link:       "/api/v1/dns/board",
		})
		stagesSeen["dns"] = true
	}
	if !stagesSeen["dns"] {
		res.Gaps = append(res.Gaps, Gap{Stage: "dns", Reason: "no DNS failure rows matched this scope", Link: "/api/v1/dns/board"})
	}

	// Connect / flow RED peers
	for _, rec := range in.FlowRecords {
		if !inWindow(rec.ObservedAt, req.Since, req.Until) {
			continue
		}
		if !matchScope(req, rec.Namespace, rec.Pod, rec.Peer, rec.Node, rec.Port) {
			continue
		}
		conf := "medium"
		summary := "flow delta peer " + rec.Peer + " port " + u16(rec.Port)
		if rec.Blocked > 0 {
			summary += ": blocked=" + u64(rec.Blocked)
			conf = "high"
			stagesSeen["policy"] = true
		}
		if rec.Retrans > 0 || rec.RTOs > 0 {
			summary += " retrans=" + u64(rec.Retrans) + " rto=" + u64(rec.RTOs)
			stagesSeen["retrans"] = true
		}
		if rec.Packets > 0 || rec.Bytes > 0 {
			stagesSeen["connect"] = true
		}
		res.Events = append(res.Events, Event{
			TS: rec.ObservedAt, Source: "flow", Stage: "connect",
			Summary: summary, Confidence: conf, Link: "/api/v1/flows/history",
		})
	}
	if !stagesSeen["connect"] {
		res.Gaps = append(res.Gaps, Gap{Stage: "connect", Reason: "no flow deltas in window for this scope", Link: "/api/v1/flows/history"})
	}

	// Netlink
	for _, ev := range in.NetlinkEvents {
		if !inWindow(ev.ObservedAt, req.Since, req.Until) {
			continue
		}
		if req.Node != "" && ev.Node != "" && !strings.EqualFold(req.Node, ev.Node) {
			continue
		}
		conf := "probable"
		if ev.Actor != nil && ev.Actor.Confidence != "" {
			conf = ev.Actor.Confidence
		}
		res.Events = append(res.Events, Event{
			TS: ev.ObservedAt, Source: "netlink", Stage: "route",
			Summary:    netlinkSummary(ev),
			Confidence: conf,
			Link:       "/api/v1/netlink",
		})
		stagesSeen["route"] = true
	}
	if !stagesSeen["route"] {
		res.Gaps = append(res.Gaps, Gap{Stage: "route", Reason: "no netlink events in window", Link: "/api/v1/netlink"})
	}

	// Policy / detective
	for _, h := range in.Detective {
		if req.Namespace != "" && h.Namespace != "" && !strings.EqualFold(req.Namespace, h.Namespace) {
			continue
		}
		if req.Pod != "" && h.Pod != "" && !strings.EqualFold(req.Pod, h.Pod) {
			continue
		}
		if req.Peer != "" && h.Peer != "" && h.Peer != req.Peer {
			continue
		}
		res.Events = append(res.Events, Event{
			TS: req.Until, Source: "detective", Stage: "policy",
			Summary: h.Summary, Confidence: stringOr(h.Confidence, "probable"),
			Link: "/api/v1/ebpf/explain",
		})
		stagesSeen["policy"] = true
	}
	if !stagesSeen["policy"] {
		res.Gaps = append(res.Gaps, Gap{Stage: "policy", Reason: "no policy-drop findings for this scope", Link: "/api/v1/ebpf/explain"})
	}

	for _, note := range in.PathNotes {
		res.Events = append(res.Events, Event{
			TS: req.Until, Source: "path", Stage: "path",
			Summary: note, Confidence: "medium", Link: "/api/v1/ebpf/path",
		})
		stagesSeen["path"] = true
	}
	if !stagesSeen["path"] {
		res.Gaps = append(res.Gaps, Gap{Stage: "path", Reason: "no path-diagnostic highlights", Link: "/api/v1/ebpf/path"})
	}

	for _, note := range in.DropNotes {
		res.Events = append(res.Events, Event{
			TS: req.Until, Source: "drop-info", Stage: "drops",
			Summary: note, Confidence: "medium", Link: "/api/v1/ebpf/drop-info",
		})
		stagesSeen["drops"] = true
		stagesSeen["retrans"] = true
	}
	if !stagesSeen["drops"] && !stagesSeen["retrans"] {
		res.Gaps = append(res.Gaps, Gap{Stage: "drops", Reason: "no kernel drop-info highlights for this scope", Link: "/api/v1/ebpf/drop-info"})
	}

	for _, c := range in.Captures {
		if req.Node != "" && c.Node != "" && !strings.EqualFold(req.Node, c.Node) {
			continue
		}
		res.Events = append(res.Events, Event{
			TS: c.StartedAt, Source: "capture", Stage: "capture",
			Summary: "capture artifact on " + c.Node, Confidence: "high",
			Link: "/api/v1/capture/history",
		})
		stagesSeen["capture"] = true
	}

	sort.SliceStable(res.Events, func(i, j int) bool {
		return res.Events[i].TS.Before(res.Events[j].TS)
	})

	res.Confidence = buildConfidence(req, in, stagesSeen)
	if len(res.Events) == 0 {
		res.Gaps = append(res.Gaps, Gap{
			Stage:  "visibility",
			Reason: "visibility ends here: no evidence matched this connection scope in the window",
		})
	} else {
		res.Gaps = append(res.Gaps, Gap{
			Stage:  "visibility",
			Reason: "visibility ends at the last evidence event; later stages without sensors are listed in gaps",
		})
	}
	return res
}

func buildConfidence(req Request, in Input, stages map[string]bool) Confidence {
	c := Confidence{Overall: "medium"}
	stale := 0
	for _, a := range in.Agents {
		if a.Stale {
			stale++
			c.StaleAttribution = append(c.StaleAttribution, "stale agent "+a.Node)
		}
	}
	if stale > 0 {
		c.Overall = "low"
	}
	for _, n := range in.Coverage.Nodes {
		for _, p := range n.Programs {
			if !p.Attached {
				c.SensorAvailability = append(c.SensorAvailability, n.Node+": "+p.Name+" not attached")
			}
		}
		for _, m := range n.MissingMaps {
			c.SensorAvailability = append(c.SensorAvailability, n.Node+": missing map "+m)
		}
	}
	if len(c.SensorAvailability) > 0 && c.Overall == "medium" {
		c.Overall = "low"
	}
	if len(in.FlowRecords) == 0 {
		c.RetentionGaps = append(c.RetentionGaps, "no flow records in window (first sample after restart is a baseline; JSON/SQLite caps apply)")
	}
	if req.Peer == "" && req.Pod == "" {
		c.Notes = append(c.Notes, "narrow the query with namespace/pod/peer for higher confidence")
	}
	if stages["connect"] && stages["policy"] && stale == 0 {
		c.Overall = "high"
	}
	if len(c.SensorAvailability) == 0 && len(c.StaleAttribution) == 0 && len(c.RetentionGaps) == 0 {
		c.Notes = append(c.Notes, "sensors reporting; confidence still limited by sampling and attribution freshness")
	}
	return c
}

func matchScope(req Request, ns, pod, peer, node string, port uint16) bool {
	if req.Namespace != "" && !strings.EqualFold(req.Namespace, ns) {
		return false
	}
	if req.Pod != "" && !strings.EqualFold(req.Pod, pod) {
		return false
	}
	if req.Peer != "" && req.Peer != peer {
		return false
	}
	if req.Node != "" && !strings.EqualFold(req.Node, node) {
		return false
	}
	if req.Port != 0 && req.Port != port {
		return false
	}
	return true
}

func inWindow(ts, since, until time.Time) bool {
	if ts.IsZero() {
		return true
	}
	if !since.IsZero() && ts.Before(since) {
		return false
	}
	if !until.IsZero() && ts.After(until) {
		return false
	}
	return true
}

func stringOr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func u64(n uint64) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(fmtInt(n), ",", ""), " ", ""))
}

func u16(n uint16) string { return fmtInt(uint64(n)) }

func fmtInt(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func netlinkSummary(ev models.NetlinkEvent) string {
	parts := []string{"netlink", ev.Kind, ev.Action}
	if ev.Interface != "" {
		parts = append(parts, "if="+ev.Interface)
	}
	if ev.Destination != "" {
		parts = append(parts, "dst="+ev.Destination)
	}
	if ev.Detail != "" {
		parts = append(parts, ev.Detail)
	}
	if ev.Origin != "" {
		parts = append(parts, "origin="+ev.Origin)
	}
	return strings.Join(parts, " ")
}
