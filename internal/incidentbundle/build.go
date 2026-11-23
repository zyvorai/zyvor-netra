// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package incidentbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/flowexport"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/talkers"
)

// MetricLine is one already-queried metric series.
type MetricLine struct {
	Context, Dimension, Units, Title, Scope string
	Start, Step                             int64
	Values                                  []float64 // NaN is a gap
}

// AlertIn is a raised metric alert.
type AlertIn struct {
	Rule, Node, Context, Chart, Dimension, Status, Units, Info string
	Value                                                      float64
	Since                                                      time.Time
	Silenced, Acked                                            bool
}

// TransitionIn is a metric alert status change.
type TransitionIn struct {
	At                                time.Time
	Rule, Node, Chart, From, To, Info string
	Silenced                          bool
}

// AnomalyIn is a node anomaly bucket (percent of samples anomalous).
type AnomalyIn struct {
	Node string
	At   time.Time
	Rate float64
}

// Options select what is built and how it is redacted.
type Options struct {
	Exclude []string
	Mask    MaskMode
	MaskKey []byte
	// MaxBytes lowers the total size bound (it can never raise it).
	MaxBytes int
}

// Inputs are the already-computed stores. Zero values are fine: a missing
// store becomes an "available: false" section with a note.
type Inputs struct {
	Now     time.Time
	Window  time.Duration
	Node    string
	Version string
	Mode    string // cluster fast-path mode
	Agents  []models.AgentStatus
	Config  models.EBPFFastPathConfig
	Gaps    []string
	Metrics []MetricLine
	// MetricsNote explains why Metrics is empty (platform disabled).
	MetricsNote  string
	Flows        []flowlog.Record
	FlowsOK      bool
	Netlink      []models.NetlinkEvent
	DNSFindings  []dnsdetect.Finding
	DNSOK        bool
	Audit        []models.AuditEvent
	Leases       []models.DenyLease
	LeaseHistory []models.LeaseEvent
	Attach       []models.BPFAttachFinding
	Drops        []models.DropDetectiveFinding
	Alerts       []AlertIn
	Transitions  []TransitionIn
	AlertsOK     bool
	Anomalies    []AnomalyIn
	Opts         Options
}

// ClampWindow bounds a requested window.
func ClampWindow(d time.Duration) (time.Duration, error) {
	if d < MinWindow || d > MaxWindow {
		return 0, fmt.Errorf("window must be between %d and %d minutes", int(MinWindow/time.Minute), int(MaxWindow/time.Minute))
	}
	return d, nil
}

// ValidSection reports whether name is a section.
func ValidSection(name string) bool { _, ok := sectionTypes[name]; return ok }

// timeLists are lists in time order: when too long, the oldest rows go first.
var timeLists = map[string]bool{"events": true, "entries": true, "leaseChanges": true, "transitions": true, "anomalies": true}

type builder struct {
	in    Inputs
	start time.Time
	end   time.Time
	r     *Redactor
}

func (b *builder) inWin(t time.Time) bool {
	return !t.IsZero() && !t.Before(b.start) && !t.After(b.end.Add(time.Minute))
}

func (b *builder) keepNode(n string) bool { return b.in.Node == "" || n == "" || n == b.in.Node }

func rfc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func capList[T any](in []T, limit int, name string, m *Meta, tail bool) []T {
	if in == nil {
		return []T{}
	}
	if len(in) <= limit {
		return in
	}
	m.Truncated = append(m.Truncated, Trunc{List: name, Total: len(in), Kept: limit})
	if tail {
		return in[len(in)-limit:]
	}
	return in[:limit]
}

func newMeta(avail bool, note string) Meta {
	return Meta{Available: avail, Note: note, Truncated: []Trunc{}}
}

// Build produces the bundle JSON (compact) and the parsed document.
func Build(in Inputs) ([]byte, *Bundle, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if _, err := ClampWindow(in.Window); err != nil {
		return nil, nil, err
	}
	in.Now = in.Now.UTC().Truncate(time.Second)
	excluded := map[string]bool{}
	for _, e := range in.Opts.Exclude {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !ValidSection(e) {
			return nil, nil, fmt.Errorf("unknown section %q (sections: %s)", e, strings.Join(SectionNames, ", "))
		}
		excluded[e] = true
	}
	b := &builder{in: in, start: in.Now.Add(-in.Window), end: in.Now, r: NewRedactor(in.Opts.Mask, in.Opts.MaskKey)}
	maxBytes := MaxTotalBytes
	if in.Opts.MaxBytes > 0 && in.Opts.MaxBytes < maxBytes {
		maxBytes = in.Opts.MaxBytes
	}

	agents := make([]models.AgentStatus, 0, len(in.Agents))
	for _, a := range in.Agents {
		if b.in.Node == "" || a.Node == b.in.Node {
			agents = append(agents, a)
		}
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Node < agents[j].Node })
	b.in.Agents = agents

	secs := map[string]any{
		SecNodes:    b.nodes(),
		SecMetrics:  b.metrics(),
		SecFlows:    b.flows(),
		SecNetwork:  b.network(),
		SecMetadata: b.metadata(),
		SecEBPF:     b.ebpf(),
		SecAudit:    b.audit(),
		SecInsights: b.insights(),
	}
	for name := range excluded {
		if name != SecTimeline {
			secs[name] = emptySection(name)
		}
	}

	// Size fit before the timeline exists, so its refs stay valid.
	reserve := 256 << 10
	b.fit(secs, maxBytes*9/10-reserve)

	if excluded[SecTimeline] {
		secs[SecTimeline] = emptySection(SecTimeline)
	} else {
		secs[SecTimeline] = b.timeline(secs)
	}

	trees := map[string]any{}
	raw := map[string]json.RawMessage{}
	total := 0
	for _, name := range SectionNames {
		tree, err := toTree(secs[name])
		if err != nil {
			return nil, nil, err
		}
		tree = b.r.Tree(tree)
		canon, err := json.Marshal(tree)
		if err != nil {
			return nil, nil, err
		}
		trees[name] = tree
		raw[name] = canon
		total += len(canon)
	}
	if total > maxBytes {
		return nil, nil, fmt.Errorf("bundle is %d bytes after truncation, over the %d byte bound", total, maxBytes)
	}

	nodeCount, stale := len(agents), 0
	for _, a := range agents {
		if a.Stale {
			stale++
		}
	}
	scope := "cluster"
	if in.Node != "" {
		scope = "node"
	}
	doc := &Bundle{
		Schema:      Schema,
		GeneratedAt: rfc(in.Now),
		Window:      Window{Start: rfc(b.start), End: rfc(b.end), Minutes: int(in.Window / time.Minute)},
		Identity: Identity{Product: "netra", Component: "netrad", Version: b.r.String(in.Version), Scope: scope,
			Node: b.r.String(in.Node), Mode: b.r.String(in.Mode), Nodes: nodeCount, StaleNodes: stale},
		Bounds: Bounds{MaxWindowMinutes: int(MaxWindow / time.Minute), MaxTotalBytes: maxBytes, MaxSeries: MaxSeries,
			MaxPoints: MaxPoints, MaxRows: maxListAny, Bytes: total},
		Sections: raw,
		Caveats:  caveats(),
	}
	ex := make([]string, 0, len(excluded))
	for n := range excluded {
		ex = append(ex, n)
	}
	sort.Strings(ex)
	doc.Redaction = Redaction{Approach: "allow-list: every section is a typed struct of permitted fields; all strings pass one scrubber; verify refuses unknown fields",
		MaskIPs: string(b.r.mode), MaskKeyID: b.r.KeyID(), ExcludedSections: ex, NeverIncluded: neverIncluded(), Applied: b.r.Applied()}
	doc.Integrity = chain(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	return out, doc, nil
}

func emptySection(name string) any {
	m := Meta{Available: false, Excluded: true, Note: "excluded by request", Truncated: []Trunc{}}
	switch name {
	case SecNodes:
		return &NodesSection{Meta: m, Items: []NodeInfo{}, Gaps: []string{}}
	case SecMetrics:
		return &MetricsSection{Meta: m, Series: []Series{}}
	case SecFlows:
		return &FlowsSection{Meta: m, Flows: []FlowRow{}, Talkers: []TalkerRow{}}
	case SecNetwork:
		return &NetworkSection{Meta: m, Events: []NetEvent{}}
	case SecMetadata:
		return &MetadataSection{Meta: m, DNSFindings: []DNSFinding{}, DNSHealth: []DNSHealthRow{}, TLS: []TLSRow{}, HTTP: []HTTPRow{}, HTTPStatus: []HTTPStatusRow{}}
	case SecEBPF:
		return &EBPFSection{Meta: m, Attachments: []AttachNode{}, Findings: []AttachFinding{}, Deny: DenyState{Counts: map[string]int{}}, Leases: []LeaseRow{}, LeaseChanges: []LeaseChange{}}
	case SecAudit:
		return &AuditSection{Meta: m, Entries: []AuditRow{}}
	case SecInsights:
		return &InsightsSection{Meta: m, Alerts: []AlertRow{}, Transitions: []AlertTransition{}, Anomalies: []AnomalyBurst{}, Drops: []DropFinding{}}
	default:
		return &TimelineSection{Meta: m, Entries: []TimelineEntry{}, Counts: map[string]int{}}
	}
}

func toTree(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return decodeTree(raw)
}

func decodeTree(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var t any
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return t, nil
}

// canon re-encodes JSON with sorted keys and literal numbers.
func canon(raw []byte) ([]byte, error) {
	t, err := decodeTree(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(t)
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// chain computes the hash chain over the section canon bytes. The seed covers
// the schema, window, identity and redaction block, so the framing is tamper
// evident too.
func chain(doc *Bundle) Integrity {
	seedDoc, _ := json.Marshal(struct {
		Schema    string    `json:"schema"`
		Window    Window    `json:"window"`
		Identity  Identity  `json:"identity"`
		Redaction Redaction `json:"redaction"`
	}{doc.Schema, doc.Window, doc.Identity, doc.Redaction})
	seedCanon, _ := canon(seedDoc)
	in := Integrity{Algorithm: "sha256", Seed: sum(seedCanon), Chain: []ChainLink{}}
	prev := in.Seed
	for _, name := range SectionNames {
		raw, ok := doc.Sections[name]
		if !ok {
			continue
		}
		c, _ := canon(raw)
		h := sum(c)
		prev = sum([]byte(prev + h))
		in.Chain = append(in.Chain, ChainLink{Section: name, SHA256: h, Chain: prev, Bytes: len(c)})
	}
	in.Head = prev
	return in
}

// fit shrinks the largest lists, halving them, until the sections fit budget.
func (b *builder) fit(secs map[string]any, budget int) {
	if budget < 1024 {
		budget = 1024
	}
	for iter := 0; iter < 200; iter++ {
		total := 0
		type cand struct {
			sec  string
			idx  int
			size int
			n    int
		}
		var best *cand
		for _, name := range SectionNames {
			sec, ok := secs[name]
			if !ok {
				continue
			}
			rv := reflect.ValueOf(sec).Elem()
			rt := rv.Type()
			for i := 0; i < rt.NumField(); i++ {
				f := rv.Field(i)
				if f.Kind() != reflect.Slice || rt.Field(i).Anonymous {
					continue
				}
				js, _ := json.Marshal(f.Interface())
				total += len(js)
				if f.Len() > 1 && (best == nil || len(js) > best.size) {
					best = &cand{name, i, len(js), f.Len()}
				}
			}
			if !ok {
				continue
			}
		}
		if total <= budget || best == nil {
			return
		}
		sec := secs[best.sec]
		rv := reflect.ValueOf(sec).Elem()
		f := rv.Field(best.idx)
		keep := f.Len() / 2
		listName := strings.Split(rv.Type().Field(best.idx).Tag.Get("json"), ",")[0]
		var cut reflect.Value
		if timeLists[listName] {
			cut = f.Slice(f.Len()-keep, f.Len())
		} else {
			cut = f.Slice(0, keep)
		}
		meta := rv.FieldByName("Meta").Addr().Interface().(*Meta)
		updated := false
		for i := range meta.Truncated {
			if meta.Truncated[i].List == listName {
				meta.Truncated[i].Kept = keep
				updated = true
			}
		}
		if !updated {
			meta.Truncated = append(meta.Truncated, Trunc{List: listName, Total: f.Len(), Kept: keep})
		}
		f.Set(reflect.AppendSlice(reflect.MakeSlice(f.Type(), 0, keep), cut))
	}
}

// ---- sections ----

func (b *builder) nodes() *NodesSection {
	s := &NodesSection{Meta: newMeta(true, ""), Items: []NodeInfo{}, Gaps: []string{}}
	for _, a := range b.in.Agents {
		ni := NodeInfo{Node: a.Node, Mode: a.Mode, Stale: a.Stale, AgeSeconds: a.AgeSeconds, StartedAt: rfc(a.AgentStartedAt),
			Interfaces: len(a.Interfaces), Hooks: a.Hooks, Standalone: a.Standalone, MTLS: a.MTLS}
		if a.Netlink != nil {
			ni.NetlinkAvailable = a.Netlink.Available
			ni.NetlinkOverruns, ni.NetlinkMissed, ni.NetlinkDropped = a.Netlink.Overruns, a.Netlink.Missed, a.Netlink.Dropped
		}
		ni.BPFAttachAvailable = a.BPFAttach != nil && a.BPFAttach.Available
		s.Items = append(s.Items, ni)
		switch {
		case a.Netlink == nil || !a.Netlink.Available:
			s.Gaps = append(s.Gaps, "netlink recorder not reporting on "+a.Node+": route, link and address changes there are invisible")
		case a.Netlink.Overruns > 0 || a.Netlink.Missed > 0:
			s.Gaps = append(s.Gaps, fmt.Sprintf("netlink recorder on %s lost events (overruns=%d missed=%d since agent start)", a.Node, a.Netlink.Overruns, a.Netlink.Missed))
		}
		if !ni.BPFAttachAvailable {
			s.Gaps = append(s.Gaps, "BPF attachment inventory not available on "+a.Node)
		}
		if a.Stale {
			s.Gaps = append(s.Gaps, "agent "+a.Node+" is stale: its data may be out of date")
		}
	}
	if len(b.in.Agents) == 0 {
		s.Gaps = append(s.Gaps, "no agents reported: only controller-side stores (audit, leases, metric alerts) can contribute")
	}
	s.Gaps = append(s.Gaps, b.in.Gaps...)
	sort.Strings(s.Gaps)
	s.Gaps = dedupe(s.Gaps)
	s.Items = capList(s.Items, MaxNodes, "items", &s.Meta, false)
	s.Gaps = capList(s.Gaps, 500, "gaps", &s.Meta, false)
	return s
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func nf(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}

func (b *builder) metrics() *MetricsSection {
	s := &MetricsSection{Meta: newMeta(len(b.in.Metrics) > 0, b.in.MetricsNote), Series: []Series{}}
	if len(b.in.Metrics) == 0 && s.Note == "" {
		s.Note = "no metric series matched the window"
	}
	lines := append([]MetricLine(nil), b.in.Metrics...)
	sort.Slice(lines, func(i, j int) bool {
		a, c := lines[i], lines[j]
		if a.Context != c.Context {
			return a.Context < c.Context
		}
		if a.Scope != c.Scope {
			return a.Scope < c.Scope
		}
		return a.Dimension < c.Dimension
	})
	cutPoints := 0
	for _, l := range lines {
		vals, start := l.Values, l.Start
		if len(vals) > MaxPoints {
			drop := len(vals) - MaxPoints
			vals = vals[drop:]
			start += int64(drop) * l.Step
			cutPoints = max(cutPoints, len(l.Values))
		}
		sr := Series{Context: l.Context, Dimension: l.Dimension, Units: l.Units, Title: l.Title, Scope: l.Scope, Start: start, Step: l.Step, Values: make([]*float64, len(vals))}
		n, sumv := 0, 0.0
		mn, mx, last := math.Inf(1), math.Inf(-1), math.NaN()
		for i, v := range vals {
			sr.Values[i] = nf(v)
			if !math.IsNaN(v) && !math.IsInf(v, 0) {
				n++
				sumv += v
				mn, mx, last = math.Min(mn, v), math.Max(mx, v), v
			}
		}
		if n > 0 {
			sr.Min, sr.Max, sr.Avg, sr.Last = nf(mn), nf(mx), nf(sumv/float64(n)), nf(last)
		}
		s.Series = append(s.Series, sr)
	}
	if cutPoints > 0 {
		s.Truncated = append(s.Truncated, Trunc{List: "points", Total: cutPoints, Kept: MaxPoints})
	}
	s.Series = capList(s.Series, MaxSeries, "series", &s.Meta, false)
	return s
}

func protoName(p *uint8) string {
	if p == nil {
		return ""
	}
	switch *p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	}
	return strconv.Itoa(int(*p))
}

func (b *builder) flows() *FlowsSection {
	s := &FlowsSection{Meta: newMeta(b.in.FlowsOK, ""), Flows: []FlowRow{}, Talkers: []TalkerRow{}}
	if !b.in.FlowsOK {
		s.Note = "flow history store not available"
	}
	var recs []flowlog.Record
	for _, r := range b.in.Flows {
		if b.inWin(r.ObservedAt) && b.keepNode(r.Node) {
			recs = append(recs, r)
		}
	}
	sum := flowexport.Build(recs, MaxFlows*4)
	s.Observed, s.Aggregated = sum.Observed, sum.Aggregated
	for _, f := range sum.Flows {
		row := FlowRow{Node: f.NetraNode, Namespace: f.NetraNamespace, Workload: f.NetraWorkload, Port: f.DestinationTransportPort,
			Protocol: protoName(f.ProtocolIdentifier), AppProto: f.NetraAppProtocol, Bytes: f.OctetDeltaCount, Packets: f.PacketDeltaCount,
			Blocked: f.NetraBlockedCount, Retransmit: f.NetraRetransmits,
			FirstSeen: rfc(time.UnixMilli(f.FlowStartMilliseconds)), LastSeen: rfc(time.UnixMilli(f.FlowEndMilliseconds))}
		if f.FlowDirection != nil {
			row.Direction = map[uint8]string{0: "ingress", 1: "egress"}[*f.FlowDirection]
		}
		switch {
		case f.NetraPeer != "":
			row.Peer = f.NetraPeer
		case f.SourceIPv4Address != "":
			row.Peer = f.SourceIPv4Address
		case f.DestinationIPv4Address != "":
			row.Peer = f.DestinationIPv4Address
		case f.SourceIPv6Address != "":
			row.Peer = f.SourceIPv6Address
		default:
			row.Peer = f.DestinationIPv6Address
		}
		row.Peer = b.r.Host(row.Peer)
		s.Flows = append(s.Flows, row)
	}
	sort.SliceStable(s.Flows, func(i, j int) bool {
		a, c := s.Flows[i], s.Flows[j]
		if a.Bytes != c.Bytes {
			return a.Bytes > c.Bytes
		}
		if a.Packets != c.Packets {
			return a.Packets > c.Packets
		}
		return fmt.Sprint(a.Node, a.Workload, a.Direction, a.Peer, a.Port, a.Protocol) < fmt.Sprint(c.Node, c.Workload, c.Direction, c.Peer, c.Port, c.Protocol)
	})
	if len(sum.Flows) > MaxFlows {
		s.Truncated = append(s.Truncated, Trunc{List: "flows", Total: s.Aggregated, Kept: MaxFlows})
		s.Flows = s.Flows[:MaxFlows]
	} else if sum.Truncated {
		s.Truncated = append(s.Truncated, Trunc{List: "flows", Total: s.Aggregated, Kept: len(s.Flows)})
	}
	board := talkers.Build(b.in.Agents, b.in.Now, MaxTalkers)
	for _, t := range board.Rows {
		s.Talkers = append(s.Talkers, TalkerRow{Destination: b.r.Host(t.Destination), Packets: t.Packets, Bytes: t.Bytes, Blocked: t.Blocked, Nodes: t.Nodes})
	}
	sort.SliceStable(s.Talkers, func(i, j int) bool {
		if s.Talkers[i].Bytes != s.Talkers[j].Bytes {
			return s.Talkers[i].Bytes > s.Talkers[j].Bytes
		}
		return s.Talkers[i].Destination < s.Talkers[j].Destination
	})
	s.Talkers = capList(s.Talkers, MaxTalkers, "talkers", &s.Meta, false)
	return s
}

func (b *builder) network() *NetworkSection {
	avail := false
	for _, a := range b.in.Agents {
		if a.Netlink != nil && a.Netlink.Available {
			avail = true
		}
	}
	s := &NetworkSection{Meta: newMeta(avail, ""), Events: []NetEvent{}}
	if !avail {
		s.Note = "no agent reported a netlink recorder"
	}
	for _, e := range b.in.Netlink {
		if !b.inWin(e.ObservedAt) || !b.keepNode(e.Node) {
			continue
		}
		ev := NetEvent{At: rfc(e.ObservedAt), Node: e.Node, Kind: e.Kind, Action: e.Action, Interface: e.Interface, Family: e.Family,
			Address: e.Address, Destination: e.Destination, Gateway: e.Gateway, Source: e.Source, State: e.State, LinkType: e.LinkType,
			MTU: e.MTU, Table: e.Table, Priority: e.Priority, Origin: e.Origin, Detail: e.Detail}
		if e.Actor != nil {
			ev.ActorComm, ev.ActorPID, ev.ActorConf = e.Actor.Comm, e.Actor.PID, e.Actor.Confidence
		}
		s.Events = append(s.Events, ev)
	}
	sort.SliceStable(s.Events, func(i, j int) bool {
		a, c := s.Events[i], s.Events[j]
		if a.At != c.At {
			return a.At < c.At
		}
		return fmt.Sprint(a.Node, a.Kind, a.Action, a.Interface, a.Address, a.Destination, a.Gateway) < fmt.Sprint(c.Node, c.Kind, c.Action, c.Interface, c.Address, c.Destination, c.Gateway)
	})
	s.Events = capList(s.Events, MaxNetEvents, "events", &s.Meta, true)
	return s
}

func topBy[T any](rows []T, limit int, name string, m *Meta, less func(a, b T) bool) []T {
	sort.SliceStable(rows, func(i, j int) bool { return less(rows[i], rows[j]) })
	return capList(rows, limit, name, m, false)
}

func (b *builder) metadata() *MetadataSection {
	s := &MetadataSection{Meta: newMeta(true, "DNS health, TLS and HTTP rows are the agents' cumulative counters since agent start; DNS findings are the detector's live findings"),
		DNSFindings: []DNSFinding{}, DNSHealth: []DNSHealthRow{}, TLS: []TLSRow{}, HTTP: []HTTPRow{}, HTTPStatus: []HTTPStatusRow{}}
	if !b.in.DNSOK {
		s.Note += "; the DNS detector is not running"
	}
	for _, f := range b.in.DNSFindings {
		if !b.keepNode(f.Node) || (!f.LastSeen.IsZero() && f.LastSeen.Before(b.start)) {
			continue
		}
		sigs := make([]string, 0, len(f.Signals))
		for _, g := range f.Signals {
			sigs = append(sigs, b.r.String(g))
		}
		s.DNSFindings = append(s.DNSFindings, DNSFinding{Type: string(f.Type), Severity: string(f.Severity), Domain: b.r.Host(f.Domain), Score: math.Round(f.Score*100) / 100,
			Signals: sigs, Node: f.Node, Namespace: f.Namespace, Workload: f.Workload, FirstSeen: rfc(f.FirstSeen), LastSeen: rfc(f.LastSeen), Count: f.Count})
	}
	for _, a := range b.in.Agents {
		for _, d := range a.DNSHealth {
			if d.Failures == 0 && d.Queries == 0 {
				continue
			}
			s.DNSHealth = append(s.DNSHealth, DNSHealthRow{Node: a.Node, Name: b.r.Host(d.Name), Queries: d.Queries, Responses: d.Responses, Failures: d.Failures,
				MaxLatencyUS: d.MaxLatencyUS, Namespace: d.Namespace, Workload: d.WorkloadName})
		}
		for _, t := range a.TLSMetadata {
			s.TLS = append(s.TLS, TLSRow{Node: a.Node, SNI: b.r.Host(t.SNI), Handshakes: t.Handshakes, Blocked: t.Blocked, Namespace: t.Namespace, Workload: t.WorkloadName})
		}
		for _, h := range a.HTTPMetadata {
			s.HTTP = append(s.HTTP, HTTPRow{Node: a.Node, Method: methodOnly(h.Method), Host: b.r.Host(h.Host), Requests: h.Requests, Namespace: h.Namespace, Workload: h.WorkloadName})
		}
		for _, h := range a.HTTPStatus {
			s.HTTPStatus = append(s.HTTPStatus, HTTPStatusRow{Node: a.Node, Status: h.Status, Count: h.Count, Namespace: h.Namespace, Workload: h.WorkloadName})
		}
	}
	s.DNSFindings = topBy(s.DNSFindings, MaxMetaRows, "dnsFindings", &s.Meta, func(a, c DNSFinding) bool {
		if a.Score != c.Score {
			return a.Score > c.Score
		}
		return a.Domain+a.Type+a.Node < c.Domain+c.Type+c.Node
	})
	s.DNSHealth = topBy(s.DNSHealth, MaxMetaRows, "dnsHealth", &s.Meta, func(a, c DNSHealthRow) bool {
		if a.Failures != c.Failures {
			return a.Failures > c.Failures
		}
		if a.Queries != c.Queries {
			return a.Queries > c.Queries
		}
		return a.Node+a.Name < c.Node+c.Name
	})
	s.TLS = topBy(s.TLS, MaxMetaRows, "tls", &s.Meta, func(a, c TLSRow) bool {
		if a.Handshakes != c.Handshakes {
			return a.Handshakes > c.Handshakes
		}
		return a.Node+a.SNI < c.Node+c.SNI
	})
	s.HTTP = topBy(s.HTTP, MaxMetaRows, "http", &s.Meta, func(a, c HTTPRow) bool {
		if a.Requests != c.Requests {
			return a.Requests > c.Requests
		}
		return a.Node+a.Host+a.Method < c.Node+c.Host+c.Method
	})
	s.HTTPStatus = topBy(s.HTTPStatus, MaxMetaRows, "httpStatus", &s.Meta, func(a, c HTTPStatusRow) bool {
		if a.Count != c.Count {
			return a.Count > c.Count
		}
		return a.Node < c.Node || (a.Node == c.Node && a.Status < c.Status)
	})
	return s
}

// methodOnly keeps a token that looks like an HTTP method.
func methodOnly(m string) string {
	if len(m) == 0 || len(m) > 16 {
		return "OTHER"
	}
	for _, c := range m {
		if c < 'A' || c > 'Z' {
			return "OTHER"
		}
	}
	return m
}

func (b *builder) ebpf() *EBPFSection {
	cfg := b.in.Config
	s := &EBPFSection{Meta: newMeta(true, ""), Attachments: []AttachNode{}, Findings: []AttachFinding{}, Leases: []LeaseRow{}, LeaseChanges: []LeaseChange{}}
	d := DenyState{Mode: cfg.Mode, Revision: cfg.Revision, ScopeMode: cfg.ScopeMode, NetPolEnabled: cfg.NetPolEnabled, LeaseSeconds: cfg.LeaseSeconds,
		Counts: map[string]int{
			"allowedCidrs": len(cfg.AllowedCIDRs), "allowedIPv4": len(cfg.AllowedIPv4), "allowedIPv6": len(cfg.AllowedIPv6),
			"allowedPorts": len(cfg.AllowedPorts), "allowedProcesses": len(cfg.AllowedProcesses), "allowedUids": len(cfg.AllowedUIDs),
			"blockedCidrs": len(cfg.BlockedCIDRs), "blockedDns": len(cfg.BlockedDNS), "blockedIPv4": len(cfg.BlockedIPv4),
			"blockedIPv6": len(cfg.BlockedIPv6), "blockedIngressIPv4": len(cfg.BlockedIngressIPv4), "blockedIngressIPv6": len(cfg.BlockedIngressIPv6),
			"blockedPorts": len(cfg.BlockedPorts), "blockedProcesses": len(cfg.BlockedProcesses), "blockedSni": len(cfg.BlockedSNI),
			"blockedUids": len(cfg.BlockedUIDs), "connRateLimits": len(cfg.ConnRateLimits), "netPolDenies": len(cfg.NetPolDenies),
			"netPolRules": len(cfg.NetPolRules), "rateLimits": len(cfg.RateLimits), "workloadScopes": len(cfg.WorkloadScopes),
		}}
	if cfg.Shield != nil {
		d.ShieldMode = cfg.Shield.Mode
	}
	if cfg.EnforceUntil != nil {
		d.LeaseExpiresAt = rfc(*cfg.EnforceUntil)
	}
	s.Deny = d

	for _, a := range b.in.Agents {
		if a.BPFAttach == nil {
			continue
		}
		r := a.BPFAttach
		n := AttachNode{Node: a.Node, Available: r.Available, Unavailable: r.Unavailable, ObservedAt: rfc(r.ObservedAt), Hash: r.Hash, Total: r.Total, Interfaces: []AttachInterface{}}
		for _, ifc := range r.Interfaces {
			ai := AttachInterface{Name: ifc.Name, Type: ifc.Type, State: ifc.State, Programs: []AttachProgram{}}
			add := func(hook string, ps ...models.BPFProgram) {
				for _, p := range ps {
					ai.Programs = append(ai.Programs, AttachProgram{Hook: hook, ID: p.ID, Name: p.Name, Owner: p.Owner, Mode: p.Mode})
				}
			}
			if ifc.XDP != nil {
				add("xdp", *ifc.XDP)
			}
			add("tcx-ingress", ifc.TCXIngress...)
			add("tcx-egress", ifc.TCXEgress...)
			add("tc-ingress", ifc.TCIngress...)
			add("tc-egress", ifc.TCEgress...)
			n.Interfaces = append(n.Interfaces, ai)
		}
		sort.SliceStable(n.Interfaces, func(i, j int) bool { return n.Interfaces[i].Name < n.Interfaces[j].Name })
		n.Interfaces = capList(n.Interfaces, MaxAttachInterface, "interfaces:"+a.Node, &s.Meta, false)
		s.Attachments = append(s.Attachments, n)
	}
	sort.SliceStable(s.Attachments, func(i, j int) bool { return s.Attachments[i].Node < s.Attachments[j].Node })
	s.Attachments = capList(s.Attachments, MaxNodes, "attachments", &s.Meta, false)

	for _, f := range b.in.Attach {
		if b.keepNode(f.Node) {
			s.Findings = append(s.Findings, AttachFinding{Severity: sev(f.Severity), Kind: f.Kind, Node: f.Node, Subject: f.Subject, Message: f.Message, Interfaces: f.Interfaces})
		}
	}
	s.Findings = topBy(s.Findings, MaxFindings, "findings", &s.Meta, func(a, c AttachFinding) bool {
		if sevRank(a.Severity) != sevRank(c.Severity) {
			return sevRank(a.Severity) > sevRank(c.Severity)
		}
		return a.Node+a.Kind+a.Subject < c.Node+c.Kind+c.Subject
	})

	for _, l := range b.in.Leases {
		s.Leases = append(s.Leases, LeaseRow{Owner: l.Owner, Type: l.Type, Key: l.Key, Summary: l.Summary, LeaseSeconds: l.LeaseSeconds,
			CreatedAt: rfc(l.CreatedAt), CreatedBy: l.CreatedBy, ExpiresAt: rfc(l.ExpiresAt), Extensions: l.Extensions})
	}
	s.Leases = topBy(s.Leases, MaxLeases, "leases", &s.Meta, func(a, c LeaseRow) bool {
		if a.ExpiresAt != c.ExpiresAt {
			return a.ExpiresAt < c.ExpiresAt
		}
		return a.Owner+a.Key < c.Owner+c.Key
	})
	for _, e := range b.in.LeaseHistory {
		if !b.inWin(e.At) {
			continue
		}
		s.LeaseChanges = append(s.LeaseChanges, LeaseChange{At: rfc(e.At), Action: e.Action, Actor: e.Actor, Owner: e.Owner, Rule: e.Rule,
			LeaseSeconds: e.LeaseSeconds, Rails: e.Rails, BreakGlass: e.BreakGlass, Reason: e.Reason})
	}
	sort.SliceStable(s.LeaseChanges, func(i, j int) bool {
		a, c := s.LeaseChanges[i], s.LeaseChanges[j]
		if a.At != c.At {
			return a.At < c.At
		}
		return a.Action+a.Owner+a.Rule < c.Action+c.Owner+c.Rule
	})
	s.LeaseChanges = capList(s.LeaseChanges, MaxLeaseEvents, "leaseChanges", &s.Meta, true)
	return s
}

func sev(s string) string {
	switch s {
	case "critical", "warning", "info":
		return s
	}
	return "info"
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	}
	return 1
}

// auditKeys are the only audit detail keys that enter a bundle, and only as
// scalar values.
var auditKeys = map[string]bool{
	"mode": true, "lease": true, "leaseSeconds": true, "risk": true, "count": true, "owner": true, "type": true, "rule": true,
	"id": true, "reason": true, "node": true, "namespace": true, "name": true, "kind": true, "revision": true, "result": true,
	"status": true, "source": true, "direction": true, "protocol": true, "port": true, "cidr": true, "ip": true, "key": true,
	"breakGlass": true, "rails": true, "plan": true, "feed": true, "format": true, "added": true, "removed": true,
}

func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case uint64:
		return strconv.FormatUint(t, 10), true
	case uint32:
		return strconv.FormatUint(uint64(t), 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case json.Number:
		return t.String(), true
	}
	return "", false
}

func (b *builder) audit() *AuditSection {
	s := &AuditSection{Meta: newMeta(true, ""), Entries: []AuditRow{}}
	for _, e := range b.in.Audit {
		if !b.inWin(e.At) {
			continue
		}
		row := AuditRow{At: rfc(e.At), Actor: e.Actor, Action: e.Action, Target: e.Target}
		for k, v := range e.Details {
			if !auditKeys[k] {
				continue
			}
			if str, ok := scalarString(v); ok {
				if row.Details == nil {
					row.Details = map[string]string{}
				}
				row.Details[k] = str
			}
		}
		if n := e.Details["node"]; n != nil {
			if ns, ok := n.(string); ok && ns != "" && !b.keepNode(ns) {
				continue
			}
		}
		s.Entries = append(s.Entries, row)
	}
	sort.SliceStable(s.Entries, func(i, j int) bool {
		a, c := s.Entries[i], s.Entries[j]
		if a.At != c.At {
			return a.At < c.At
		}
		return a.Actor+a.Action+a.Target < c.Actor+c.Action+c.Target
	})
	s.Entries = capList(s.Entries, MaxAudit, "entries", &s.Meta, true)
	return s
}

func (b *builder) insights() *InsightsSection {
	s := &InsightsSection{Meta: newMeta(b.in.AlertsOK, ""), Alerts: []AlertRow{}, Transitions: []AlertTransition{}, Anomalies: []AnomalyBurst{}, Drops: []DropFinding{}}
	if !b.in.AlertsOK {
		s.Note = "metric alerts are disabled: alerts and transitions are not part of this bundle"
	}
	for _, a := range b.in.Alerts {
		if !b.keepNode(a.Node) {
			continue
		}
		s.Alerts = append(s.Alerts, AlertRow{Rule: a.Rule, Node: a.Node, Context: a.Context, Chart: a.Chart, Dimension: a.Dimension, Status: a.Status,
			Value: nf(a.Value), Units: a.Units, Since: rfc(a.Since), Info: a.Info, Silenced: a.Silenced, Acked: a.Acked})
	}
	s.Alerts = topBy(s.Alerts, MaxAlerts, "alerts", &s.Meta, func(a, c AlertRow) bool {
		if a.Status != c.Status {
			return a.Status == "critical"
		}
		return a.Rule+a.Node+a.Chart < c.Rule+c.Node+c.Chart
	})
	for _, t := range b.in.Transitions {
		if !b.inWin(t.At) || !b.keepNode(t.Node) {
			continue
		}
		s.Transitions = append(s.Transitions, AlertTransition{At: rfc(t.At), Rule: t.Rule, Node: t.Node, Chart: t.Chart, From: t.From, To: t.To, Info: t.Info, Silenced: t.Silenced})
	}
	sort.SliceStable(s.Transitions, func(i, j int) bool {
		a, c := s.Transitions[i], s.Transitions[j]
		if a.At != c.At {
			return a.At < c.At
		}
		return a.Rule+a.Node+a.Chart < c.Rule+c.Node+c.Chart
	})
	s.Transitions = capList(s.Transitions, MaxAlertChanges, "transitions", &s.Meta, true)
	for _, a := range b.in.Anomalies {
		if !b.inWin(a.At) || !b.keepNode(a.Node) || a.Rate < burstMin || math.IsNaN(a.Rate) {
			continue
		}
		s.Anomalies = append(s.Anomalies, AnomalyBurst{At: rfc(a.At), Node: a.Node, RatePercent: math.Round(a.Rate*10) / 10})
	}
	sort.SliceStable(s.Anomalies, func(i, j int) bool {
		a, c := s.Anomalies[i], s.Anomalies[j]
		if a.At != c.At {
			return a.At < c.At
		}
		return a.Node < c.Node
	})
	s.Anomalies = capList(s.Anomalies, MaxAnomalies, "anomalies", &s.Meta, true)
	for _, d := range b.in.Drops {
		if !b.keepNode(d.Node) {
			continue
		}
		s.Drops = append(s.Drops, DropFinding{Node: d.Node, Confidence: d.Confidence, Code: d.Code, Stage: d.Stage, Direction: d.Direction, Protocol: d.Protocol,
			Src: d.Src, Dst: d.Dst, Packets: d.Packets, Bytes: d.Bytes, Explanation: d.Explanation, Namespace: d.Namespace, Pod: d.Pod})
	}
	s.Drops = topBy(s.Drops, MaxDrops, "drops", &s.Meta, func(a, c DropFinding) bool {
		if a.Packets != c.Packets {
			return a.Packets > c.Packets
		}
		return a.Node+a.Code+a.Src+a.Dst < c.Node+c.Code+c.Src+c.Dst
	})
	return s
}

// burstMin is the percent of anomalous samples in a bucket that counts as a burst.
const burstMin = 20.0

// ---- timeline ----

func (b *builder) timeline(secs map[string]any) *TimelineSection {
	s := &TimelineSection{Meta: newMeta(true, "ordering is not causation; entries without a time are current state"), Entries: []TimelineEntry{}, Counts: map[string]int{}}
	add := func(at, cat, class, sevr, node, summary, ref string) {
		s.Entries = append(s.Entries, TimelineEntry{At: at, AtKnown: at != "", Category: cat, Class: class, Severity: sevr, Node: node, Summary: summary, Ref: ref})
	}
	if n, ok := secs[SecNetwork].(*NetworkSection); ok {
		for i, e := range n.Events {
			sv, class := "info", "change"
			if e.Kind == "overrun" {
				sv, class = "warning", "context"
			}
			what := firstNonEmpty(e.Destination, e.Address, e.Interface)
			sum := fmt.Sprintf("%s %s %s", e.Kind, e.Action, what)
			if e.Gateway != "" {
				sum += " via " + e.Gateway
			}
			if e.Interface != "" && what != e.Interface {
				sum += " dev " + e.Interface
			}
			if e.ActorComm != "" {
				sum += fmt.Sprintf(" (by %s pid %d)", e.ActorComm, e.ActorPID)
			} else if e.Detail != "" {
				sum += " (" + e.Detail + ")"
			}
			add(e.At, "network", class, sv, e.Node, sum, fmt.Sprintf("%s/events/%d", SecNetwork, i))
		}
	}
	if a, ok := secs[SecAudit].(*AuditSection); ok {
		for i, e := range a.Entries {
			sum := e.Actor + " " + e.Action
			if e.Target != "" {
				sum += " " + e.Target
			}
			add(e.At, "audit", "change", "info", e.Details["node"], sum, fmt.Sprintf("%s/entries/%d", SecAudit, i))
		}
	}
	if e, ok := secs[SecEBPF].(*EBPFSection); ok {
		for i, c := range e.LeaseChanges {
			sv, class := "info", "change"
			if c.Action == "reject" {
				sv = "warning"
			}
			if c.Action == "expire" {
				class = "context"
			}
			sum := fmt.Sprintf("deny lease %s %s", c.Action, firstNonEmpty(c.Rule, c.Owner))
			if c.BreakGlass {
				sum += " (break-glass)"
				sv = "warning"
			}
			add(c.At, "lease", class, sv, "", sum, fmt.Sprintf("%s/leaseChanges/%d", SecEBPF, i))
		}
		for i, f := range e.Findings {
			add("", "ebpf", "state", f.Severity, f.Node, f.Kind+": "+f.Message, fmt.Sprintf("%s/findings/%d", SecEBPF, i))
		}
	}
	if in, ok := secs[SecInsights].(*InsightsSection); ok {
		for i, t := range in.Transitions {
			class, sv := "context", "info"
			switch t.To {
			case "critical":
				class, sv = "break", "critical"
			case "warning":
				class, sv = "break", "warning"
			}
			add(t.At, "alert", class, sv, t.Node, fmt.Sprintf("alert %s on %s %s -> %s", t.Rule, t.Node, t.From, t.To), fmt.Sprintf("%s/transitions/%d", SecInsights, i))
		}
		for i, a := range in.Anomalies {
			sv := "warning"
			if a.RatePercent >= 50 {
				sv = "critical"
			}
			add(a.At, "anomaly", "break", sv, a.Node, fmt.Sprintf("%.0f%% of samples anomalous on %s", a.RatePercent, a.Node), fmt.Sprintf("%s/anomalies/%d", SecInsights, i))
		}
		for i, d := range in.Drops {
			add("", "finding", "state", "warning", d.Node, fmt.Sprintf("drops: %s at %s (%d packets)", d.Code, d.Stage, d.Packets), fmt.Sprintf("%s/drops/%d", SecInsights, i))
		}
		for i, a := range in.Alerts {
			sv := sev(a.Status)
			add("", "alert", "state", sv, a.Node, fmt.Sprintf("alert %s raised (%s) on %s", a.Rule, a.Status, a.Node), fmt.Sprintf("%s/alerts/%d", SecInsights, i))
		}
	}
	if m, ok := secs[SecMetadata].(*MetadataSection); ok {
		for i, f := range m.DNSFindings {
			add(f.LastSeen, "finding", "break", sev(f.Severity), f.Node, fmt.Sprintf("dns %s on %s (score %.2f)", f.Type, f.Domain, f.Score), fmt.Sprintf("%s/dnsFindings/%d", SecMetadata, i))
		}
	}
	sort.SliceStable(s.Entries, func(i, j int) bool {
		a, c := s.Entries[i], s.Entries[j]
		if a.AtKnown != c.AtKnown {
			return a.AtKnown
		}
		if a.At != c.At {
			return a.At < c.At
		}
		if !a.AtKnown && sevRank(a.Severity) != sevRank(c.Severity) {
			return sevRank(a.Severity) > sevRank(c.Severity)
		}
		return a.Ref < c.Ref
	})
	if len(s.Entries) > MaxTimeline {
		s.Truncated = append(s.Truncated, Trunc{List: "entries", Total: len(s.Entries), Kept: MaxTimeline})
		// Keep the newest timed entries; untimed state entries sort last and
		// are kept first because they describe the present.
		var timed, state []TimelineEntry
		for _, e := range s.Entries {
			if e.AtKnown {
				timed = append(timed, e)
			} else {
				state = append(state, e)
			}
		}
		if len(state) > MaxTimeline/4 {
			state = state[:MaxTimeline/4]
		}
		room := MaxTimeline - len(state)
		if len(timed) > room {
			timed = timed[len(timed)-room:]
		}
		s.Entries = append(timed, state...)
	}
	for _, e := range s.Entries {
		s.Counts[e.Class]++
		s.Counts["category:"+e.Category]++
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
