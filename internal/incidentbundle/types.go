// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package incidentbundle builds the incident flight recorder bundle: one
// portable, versioned JSON document that answers "what did the network look
// like on this node in the last N minutes" from stores Netra already keeps.
//
// It is a read-only view. It adds no collector and captures no new data: every
// field comes from an already-aggregated store (metrics, flow deltas, netlink
// history, agent-reported metadata counters, BPF attachment inventory, lease
// history, the audit trail, metric alerts). Redaction is by construction: each
// section is a typed struct that lists the fields allowed into the bundle, every
// string then passes one scrubber, and Verify decodes with unknown fields
// refused. No payload bytes, command lines, environment, Secret contents or
// full URLs with query strings or credentials can be represented.
package incidentbundle

import (
	"encoding/json"
	"time"
)

// Schema is the bundle schema identifier.
const Schema = "netra-incident-bundle/1"

// Hard bounds. A request may ask for less, never for more.
const (
	MaxWindow          = 24 * time.Hour
	DefaultWindow      = 15 * time.Minute
	MinWindow          = time.Minute
	MaxTotalBytes      = 8 << 20
	MaxSeries          = 60
	MaxPoints          = 120
	MaxFlows           = 100
	MaxTalkers         = 50
	MaxNetEvents       = 500
	MaxMetaRows        = 50
	MaxNodes           = 200
	MaxAttachInterface = 64
	MaxLeases          = 200
	MaxLeaseEvents     = 200
	MaxAudit           = 300
	MaxAlerts          = 100
	MaxAlertChanges    = 200
	MaxAnomalies       = 200
	MaxDrops           = 100
	MaxFindings        = 100
	MaxTimeline        = 1000
	maxListAny         = 4096 // verify: no list in any section may exceed this
)

// Section names, in bundle (and hash chain) order.
const (
	SecNodes    = "nodes"
	SecMetrics  = "metrics"
	SecFlows    = "flows"
	SecNetwork  = "network_changes"
	SecMetadata = "metadata"
	SecEBPF     = "ebpf"
	SecAudit    = "audit"
	SecInsights = "insights"
	SecTimeline = "timeline"
)

// SectionNames is the fixed section order.
var SectionNames = []string{SecNodes, SecMetrics, SecFlows, SecNetwork, SecMetadata, SecEBPF, SecAudit, SecInsights, SecTimeline}

// Bundle is the document. Sections stay raw so their canonical bytes can be
// hashed exactly as written; encoding/json writes map keys sorted, so the file
// is deterministic.
type Bundle struct {
	Schema      string                     `json:"schema"`
	GeneratedAt string                     `json:"generatedAt"`
	Window      Window                     `json:"window"`
	Identity    Identity                   `json:"identity"`
	Redaction   Redaction                  `json:"redaction"`
	Bounds      Bounds                     `json:"bounds"`
	Sections    map[string]json.RawMessage `json:"sections"`
	Integrity   Integrity                  `json:"integrity"`
	Caveats     []string                   `json:"caveats"`
}

// Window is the recorded time range.
type Window struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Minutes int    `json:"minutes"`
}

// Identity says whose bundle this is.
type Identity struct {
	Product    string `json:"product"`
	Component  string `json:"component"`
	Version    string `json:"version"`
	Scope      string `json:"scope"`          // "cluster" or "node"
	Node       string `json:"node,omitempty"` // the node filter, when scope is node
	Mode       string `json:"mode"`           // observe | enforce (cluster fast-path mode)
	Nodes      int    `json:"nodes"`          // agents considered
	StaleNodes int    `json:"staleNodes"`
}

// Redaction states exactly what was removed or masked.
type Redaction struct {
	Approach         string        `json:"approach"`
	MaskIPs          string        `json:"maskIps"`
	MaskKeyID        string        `json:"maskKeyId,omitempty"`
	ExcludedSections []string      `json:"excludedSections"`
	NeverIncluded    []Omitted     `json:"neverIncluded"`
	Applied          []AppliedRule `json:"applied"`
}

// Omitted names fields a section deliberately never carries.
type Omitted struct {
	Section string   `json:"section"`
	Fields  []string `json:"fields"`
	Reason  string   `json:"reason"`
}

// AppliedRule counts how often a scrub rule fired while building the bundle.
type AppliedRule struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// Bounds states the limits this bundle was built under.
type Bounds struct {
	MaxWindowMinutes int `json:"maxWindowMinutes"`
	MaxTotalBytes    int `json:"maxTotalBytes"`
	MaxSeries        int `json:"maxSeries"`
	MaxPoints        int `json:"maxPointsPerSeries"`
	MaxRows          int `json:"maxRowsPerList"`
	Bytes            int `json:"bytes"` // size of the sections as written
}

// Integrity is a hash chain over the sections. It makes accidental or casual
// tampering visible; it is not a signature and does not prove who made it.
type Integrity struct {
	Algorithm string      `json:"algorithm"`
	Seed      string      `json:"seed"`
	Chain     []ChainLink `json:"chain"`
	Head      string      `json:"head"`
}

// ChainLink is one section's hash and its place in the chain.
type ChainLink struct {
	Section string `json:"section"`
	SHA256  string `json:"sha256"`
	Chain   string `json:"chain"`
	Bytes   int    `json:"bytes"`
}

// Trunc records a list that was cut to fit a bound.
type Trunc struct {
	List  string `json:"list"`
	Total int    `json:"total"`
	Kept  int    `json:"kept"`
}

// Meta is embedded in every section.
type Meta struct {
	Available bool    `json:"available"`
	Excluded  bool    `json:"excluded,omitempty"`
	Note      string  `json:"note,omitempty"`
	Truncated []Trunc `json:"truncated"`
}

// NodeInfo is one agent's identity and recorder health.
type NodeInfo struct {
	Node               string   `json:"node"`
	Mode               string   `json:"mode,omitempty"`
	Stale              bool     `json:"stale"`
	AgeSeconds         int64    `json:"ageSeconds"`
	StartedAt          string   `json:"startedAt,omitempty"`
	Interfaces         int      `json:"interfaces"`
	Hooks              []string `json:"hooks,omitempty"`
	Standalone         bool     `json:"standalone"`
	MTLS               bool     `json:"mtls,omitempty"`
	NetlinkAvailable   bool     `json:"netlinkAvailable"`
	NetlinkOverruns    uint64   `json:"netlinkOverruns,omitempty"`
	NetlinkMissed      uint64   `json:"netlinkMissed,omitempty"`
	NetlinkDropped     uint64   `json:"netlinkDropped,omitempty"`
	BPFAttachAvailable bool     `json:"bpfAttachAvailable"`
}

// NodesSection is the "nodes" section.
type NodesSection struct {
	Meta
	Items []NodeInfo `json:"items"`
	Gaps  []string   `json:"gaps"`
}

// Series is one bounded metric line.
type Series struct {
	Context   string     `json:"context"`
	Dimension string     `json:"dimension"`
	Units     string     `json:"units,omitempty"`
	Title     string     `json:"title,omitempty"`
	Scope     string     `json:"scope"` // node name or "all"
	Start     int64      `json:"startUnix"`
	Step      int64      `json:"stepSeconds"`
	Values    []*float64 `json:"values"`
	Min       *float64   `json:"min,omitempty"`
	Max       *float64   `json:"max,omitempty"`
	Avg       *float64   `json:"avg,omitempty"`
	Last      *float64   `json:"last,omitempty"`
}

// MetricsSection is the "metrics" section: key signals, bounded points.
type MetricsSection struct {
	Meta
	Series []Series `json:"series"`
}

// FlowRow is one aggregated flow summary (never a packet).
type FlowRow struct {
	Node       string `json:"node,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Workload   string `json:"workload,omitempty"`
	Direction  string `json:"direction,omitempty"`
	Peer       string `json:"peer,omitempty"`
	Port       uint16 `json:"port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	AppProto   string `json:"appProtocol,omitempty"`
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	Blocked    uint64 `json:"blocked,omitempty"`
	Retransmit uint64 `json:"retransmissions,omitempty"`
	FirstSeen  string `json:"firstSeen,omitempty"`
	LastSeen   string `json:"lastSeen,omitempty"`
}

// TalkerRow is one top destination from the agents' counters.
type TalkerRow struct {
	Destination string `json:"destination"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	Blocked     uint64 `json:"blocked"`
	Nodes       int    `json:"nodes"`
}

// FlowsSection is the "flows" section.
type FlowsSection struct {
	Meta
	Observed   int         `json:"observedDeltas"`
	Aggregated int         `json:"aggregated"`
	Flows      []FlowRow   `json:"flows"`
	Talkers    []TalkerRow `json:"talkers"`
}

// NetEvent is one netlink change (link, address, route, neighbour).
type NetEvent struct {
	At          string `json:"at"`
	Node        string `json:"node,omitempty"`
	Kind        string `json:"kind"`
	Action      string `json:"action"`
	Interface   string `json:"interface,omitempty"`
	Family      string `json:"family,omitempty"`
	Address     string `json:"address,omitempty"`
	Destination string `json:"destination,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Source      string `json:"source,omitempty"`
	State       string `json:"state,omitempty"`
	LinkType    string `json:"linkType,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	Table       int    `json:"table,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	Origin      string `json:"origin,omitempty"`
	ActorComm   string `json:"actorComm,omitempty"`
	ActorPID    uint32 `json:"actorPid,omitempty"`
	ActorConf   string `json:"actorConfidence,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// NetworkSection is the "network_changes" section.
type NetworkSection struct {
	Meta
	Events []NetEvent `json:"events"`
}

// DNSFinding is one DNS detector finding, without the queried labels.
type DNSFinding struct {
	Type      string   `json:"type"`
	Severity  string   `json:"severity"`
	Domain    string   `json:"domain"`
	Score     float64  `json:"score"`
	Signals   []string `json:"signals,omitempty"`
	Node      string   `json:"node,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Workload  string   `json:"workload,omitempty"`
	FirstSeen string   `json:"firstSeen,omitempty"`
	LastSeen  string   `json:"lastSeen,omitempty"`
	Count     uint64   `json:"count"`
}

// DNSHealthRow is a resolver-name counter row (cumulative since agent start).
type DNSHealthRow struct {
	Node         string `json:"node"`
	Name         string `json:"name"`
	Queries      uint64 `json:"queries"`
	Responses    uint64 `json:"responses"`
	Failures     uint64 `json:"failures"`
	MaxLatencyUS uint64 `json:"maxLatencyUs,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Workload     string `json:"workload,omitempty"`
}

// TLSRow is SNI handshake counts (cumulative since agent start).
type TLSRow struct {
	Node       string `json:"node"`
	SNI        string `json:"sni"`
	Handshakes uint64 `json:"handshakes"`
	Blocked    uint64 `json:"blocked"`
	Namespace  string `json:"namespace,omitempty"`
	Workload   string `json:"workload,omitempty"`
}

// HTTPRow is a (method, host) request count; never a path or header.
type HTTPRow struct {
	Node      string `json:"node"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Requests  uint64 `json:"requests"`
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload,omitempty"`
}

// HTTPStatusRow is a cleartext HTTP/1 status code count.
type HTTPStatusRow struct {
	Node      string `json:"node"`
	Status    uint16 `json:"status"`
	Count     uint64 `json:"count"`
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload,omitempty"`
}

// MetadataSection is the "metadata" section: DNS, TLS and HTTP metadata.
type MetadataSection struct {
	Meta
	DNSFindings []DNSFinding    `json:"dnsFindings"`
	DNSHealth   []DNSHealthRow  `json:"dnsHealth"`
	TLS         []TLSRow        `json:"tls"`
	HTTP        []HTTPRow       `json:"http"`
	HTTPStatus  []HTTPStatusRow `json:"httpStatus"`
}

// AttachProgram is a BPF program id, name and owner class.
type AttachProgram struct {
	Hook  string `json:"hook"`
	ID    uint32 `json:"id"`
	Name  string `json:"name,omitempty"`
	Owner string `json:"owner"`
	Mode  string `json:"mode,omitempty"`
}

// AttachInterface is what the kernel reports on one interface.
type AttachInterface struct {
	Name     string          `json:"name"`
	Type     string          `json:"type,omitempty"`
	State    string          `json:"state,omitempty"`
	Programs []AttachProgram `json:"programs"`
}

// AttachNode is one node's attachment inventory.
type AttachNode struct {
	Node        string            `json:"node"`
	Available   bool              `json:"available"`
	Unavailable string            `json:"unavailable,omitempty"`
	ObservedAt  string            `json:"observedAt,omitempty"`
	Hash        string            `json:"hash,omitempty"`
	Total       int               `json:"total"`
	Interfaces  []AttachInterface `json:"interfaces"`
}

// AttachFinding is a BPF attachment finding.
type AttachFinding struct {
	Severity   string   `json:"severity"`
	Kind       string   `json:"kind"`
	Node       string   `json:"node"`
	Subject    string   `json:"subject,omitempty"`
	Message    string   `json:"message"`
	Interfaces []string `json:"interfaces,omitempty"`
}

// DenyState counts the cluster deny and allow state by kind. Counts only: the
// rule values themselves are not listed (leases below carry the live bounded
// ones).
type DenyState struct {
	Mode           string         `json:"mode"`
	Counts         map[string]int `json:"counts"`
	Revision       uint64         `json:"revision"`
	ScopeMode      string         `json:"scopeMode,omitempty"`
	NetPolEnabled  bool           `json:"netPolEnabled,omitempty"`
	ShieldMode     string         `json:"shieldMode,omitempty"`
	LeaseSeconds   int64          `json:"leaseSeconds,omitempty"`
	LeaseExpiresAt string         `json:"leaseExpiresAt,omitempty"`
}

// LeaseRow is one live deny lease.
type LeaseRow struct {
	Owner        string `json:"owner"`
	Type         string `json:"type"`
	Key          string `json:"key"`
	Summary      string `json:"summary"`
	LeaseSeconds int64  `json:"leaseSeconds"`
	CreatedAt    string `json:"createdAt"`
	CreatedBy    string `json:"createdBy,omitempty"`
	ExpiresAt    string `json:"expiresAt"`
	Extensions   int    `json:"extensions,omitempty"`
}

// LeaseChange is one lease history entry in the window.
type LeaseChange struct {
	At           string   `json:"at"`
	Action       string   `json:"action"`
	Actor        string   `json:"actor,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	LeaseSeconds int64    `json:"leaseSeconds,omitempty"`
	Rails        []string `json:"rails,omitempty"`
	BreakGlass   bool     `json:"breakGlass,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// EBPFSection is the "ebpf" section.
type EBPFSection struct {
	Meta
	Attachments  []AttachNode    `json:"attachments"`
	Findings     []AttachFinding `json:"findings"`
	Deny         DenyState       `json:"deny"`
	Leases       []LeaseRow      `json:"leases"`
	LeaseChanges []LeaseChange   `json:"leaseChanges"`
}

// AuditRow is one audit entry with allow-listed scalar details.
type AuditRow struct {
	At      string            `json:"at"`
	Actor   string            `json:"actor"`
	Action  string            `json:"action"`
	Target  string            `json:"target,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// AuditSection is the "audit" section.
type AuditSection struct {
	Meta
	Entries []AuditRow `json:"entries"`
}

// AlertRow is a raised metric alert.
type AlertRow struct {
	Rule      string   `json:"rule"`
	Node      string   `json:"node"`
	Context   string   `json:"context"`
	Chart     string   `json:"chart"`
	Dimension string   `json:"dimension,omitempty"`
	Status    string   `json:"status"`
	Value     *float64 `json:"value,omitempty"`
	Units     string   `json:"units,omitempty"`
	Since     string   `json:"since"`
	Info      string   `json:"info,omitempty"`
	Silenced  bool     `json:"silenced,omitempty"`
	Acked     bool     `json:"acked,omitempty"`
}

// AlertTransition is a status change inside the window.
type AlertTransition struct {
	At       string `json:"at"`
	Rule     string `json:"rule"`
	Node     string `json:"node"`
	Chart    string `json:"chart,omitempty"`
	From     string `json:"from"`
	To       string `json:"to"`
	Info     string `json:"info,omitempty"`
	Silenced bool   `json:"silenced,omitempty"`
}

// AnomalyBurst is a node anomaly rate bucket at or above the burst threshold.
type AnomalyBurst struct {
	At          string  `json:"at"`
	Node        string  `json:"node"`
	RatePercent float64 `json:"ratePercent"`
}

// DropFinding is a drop attribution finding.
type DropFinding struct {
	Node        string `json:"node,omitempty"`
	Confidence  string `json:"confidence"`
	Code        string `json:"code"`
	Stage       string `json:"stage"`
	Direction   uint8  `json:"direction,omitempty"`
	Protocol    uint8  `json:"protocol,omitempty"`
	Src         string `json:"src,omitempty"`
	Dst         string `json:"dst,omitempty"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes,omitempty"`
	Explanation string `json:"explanation"`
	Namespace   string `json:"namespace,omitempty"`
	Pod         string `json:"pod,omitempty"`
}

// InsightsSection is the "insights" section: what is anomalous or alerting.
type InsightsSection struct {
	Meta
	Alerts      []AlertRow        `json:"alerts"`
	Transitions []AlertTransition `json:"transitions"`
	Anomalies   []AnomalyBurst    `json:"anomalies"`
	Drops       []DropFinding     `json:"drops"`
}

// TimelineEntry is one point of the computed "what changed in the window".
type TimelineEntry struct {
	At       string `json:"at,omitempty"`
	AtKnown  bool   `json:"atKnown"`
	Category string `json:"category"` // network | audit | lease | alert | anomaly | finding | ebpf
	Class    string `json:"class"`    // change | break | context | state
	Severity string `json:"severity"` // info | warning | critical
	Node     string `json:"node,omitempty"`
	Summary  string `json:"summary"`
	Ref      string `json:"ref"` // section/list/index pointer into this bundle
}

// TimelineSection is the "timeline" section.
type TimelineSection struct {
	Meta
	Entries []TimelineEntry `json:"entries"`
	Counts  map[string]int  `json:"counts"`
}

// sectionTypes decode each section strictly.
var sectionTypes = map[string]func() any{
	SecNodes:    func() any { return &NodesSection{} },
	SecMetrics:  func() any { return &MetricsSection{} },
	SecFlows:    func() any { return &FlowsSection{} },
	SecNetwork:  func() any { return &NetworkSection{} },
	SecMetadata: func() any { return &MetadataSection{} },
	SecEBPF:     func() any { return &EBPFSection{} },
	SecAudit:    func() any { return &AuditSection{} },
	SecInsights: func() any { return &InsightsSection{} },
	SecTimeline: func() any { return &TimelineSection{} },
}

// listLimits bound the top-level list of that name in any section.
var listLimits = map[string]int{
	"items": MaxNodes, "series": MaxSeries, "flows": MaxFlows, "talkers": MaxTalkers, "events": MaxNetEvents,
	"dnsFindings": MaxMetaRows, "dnsHealth": MaxMetaRows, "tls": MaxMetaRows, "http": MaxMetaRows, "httpStatus": MaxMetaRows,
	"attachments": MaxNodes, "findings": MaxFindings, "leases": MaxLeases, "leaseChanges": MaxLeaseEvents,
	"entries": MaxTimeline, "alerts": MaxAlerts, "transitions": MaxAlertChanges, "anomalies": MaxAnomalies, "drops": MaxDrops,
	"gaps": 500, "truncated": 600,
}

// neverIncluded is the per-section statement of what cannot appear. It is
// written into every bundle's redaction block.
func neverIncluded() []Omitted {
	return []Omitted{
		{SecFlows, []string{"payload or packet bytes", "local address", "pid", "comm", "dnsName", "tlsSni"}, "flows are per-peer aggregates of retained deltas; only the allow-listed columns exist"},
		{SecNetwork, []string{"mac address", "argv", "environment", "message bytes beyond the typed fields"}, "requester attribution is comm, pid and confidence only"},
		{SecMetadata, []string{"queried subdomain labels", "example query names", "URL path", "query string", "header", "cookie", "body", "JA3 or JA4 hashes"}, "DNS findings keep the registered domain and signal names; HTTP keeps method and host; TLS keeps SNI and counts"},
		{SecEBPF, []string{"rule values", "bytecode", "map contents", "workload inventory"}, "deny state is counts plus live leases; attachments are ids, names and owner classes"},
		{SecAudit, []string{"request bodies", "details keys outside the allow-list", "non-scalar details"}, "audit details are reduced to a fixed key allow-list of scalar values"},
		{SecMetrics, []string{"label values", "process names", "cgroup paths"}, "series are key signals only, by context and dimension"},
		{SecInsights, []string{"process command lines", "comm", "pid", "uid"}, "alerts, transitions, anomaly buckets and drop attribution without process identity"},
		{SecTimeline, []string{"anything not already in another section"}, "the timeline only points into the sections above"},
	}
}

func caveats() []string {
	return []string{
		"A bundle is a view over Netra's existing in-memory and sidecar stores. It records nothing new: a store that was off, overran or restarted inside the window shows as a gap, not as quiet.",
		"Metadata counters (DNS health, TLS, HTTP) are the agents' cumulative counters since agent start, not windowed deltas.",
		"The hash chain makes tampering visible to anyone holding the bundle; it is not a signature and does not prove who produced it.",
		"Ordering in the timeline is not causation.",
	}
}
