// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package models

import "time"

// Netlink event kinds. "overrun" is synthetic: the recorder itself lost kernel
// messages (ENOBUFS) or a subscription, so the change history has a gap.
const (
	NetlinkKindLink     = "link"
	NetlinkKindAddress  = "address"
	NetlinkKindRoute    = "route"
	NetlinkKindNeighbor = "neighbor"
	NetlinkKindOverrun  = "overrun"
)

// NetlinkEvent is one metadata-only RTNL control-plane change. It contains no
// packet payload, process command line, or Kubernetes Secret data.
type NetlinkEvent struct {
	// Epoch identifies the agent process that assigned Sequence; Sequence only
	// grows within one epoch, so (Epoch, Sequence) is a stable identity.
	Epoch          int64     `json:"epoch,omitempty"`
	Sequence       uint64    `json:"sequence"`
	ObservedAt     time.Time `json:"observedAt"`
	Node           string    `json:"node,omitempty"`
	Kind           string    `json:"kind"`   // link|address|route|neighbor|overrun
	Action         string    `json:"action"` // new|delete
	InterfaceIndex int       `json:"interfaceIndex,omitempty"`
	Interface      string    `json:"interface,omitempty"`
	Family         string    `json:"family,omitempty"`
	Address        string    `json:"address,omitempty"`
	Destination    string    `json:"destination,omitempty"`
	Gateway        string    `json:"gateway,omitempty"`
	Source         string    `json:"source,omitempty"`
	MAC            string    `json:"mac,omitempty"`
	State          string    `json:"state,omitempty"`
	LinkType       string    `json:"linkType,omitempty"`
	Flags          string    `json:"flags,omitempty"`
	MasterIndex    int       `json:"masterIndex,omitempty"`
	MTU            int       `json:"mtu,omitempty"`
	Table          int       `json:"table,omitempty"`
	Priority       int       `json:"priority,omitempty"`
	// Detail carries the reason for a synthetic overrun event.
	Detail string `json:"detail,omitempty"`
	// Origin says whether a process asked for this change: "process" (Actor names
	// it), "kernel" (no process requested it: carrier loss, kernel timers, router
	// advertisements) or empty when that is not known, which is the case whenever
	// the attribution sensor is not running or dropped requests around this time.
	Origin string `json:"origin,omitempty"`
	// Actor is the process that requested the change, when Origin is "process".
	Actor *NetlinkActor `json:"actor,omitempty"`
}

// Netlink change origins and actor confidences.
const (
	NetlinkOriginProcess = "process"
	NetlinkOriginKernel  = "kernel"

	NetlinkActorProbable  = "probable"  // exactly one requester matches
	NetlinkActorAmbiguous = "ambiguous" // several requesters match; none is named
)

// NetlinkActor is the process behind a recorded change, joined to it by message
// type, interface and time. It is a join, not proof: "probable" means exactly one
// requester issued a matching request at that moment, and two requesters in the
// same instant are reported as ambiguous rather than picked between. Only the
// process name, ids and cgroup are captured; never argv, environment or message content.
type NetlinkActor struct {
	Confidence string `json:"confidence"`
	Comm       string `json:"comm,omitempty"`
	PID        uint32 `json:"pid,omitempty"`
	CgroupID   uint64 `json:"cgroupId,omitempty"`
	// Namespace, Pod and Workload are the requester's pod, when its cgroup is one
	// the agent knows; empty for a host process.
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Workload  string `json:"workload,omitempty"`
	// Candidates is how many distinct requesters matched; Alternatives names up to
	// three of their processes when the match is ambiguous.
	Candidates   int      `json:"candidates,omitempty"`
	Alternatives []string `json:"alternatives,omitempty"`
}

// NetlinkActorStatus is the attribution sensor's state on one node. It is what
// makes "origin: kernel" trustworthy: it is only claimed while Available.
type NetlinkActorStatus struct {
	Available   bool   `json:"available"`
	Unavailable string `json:"unavailable,omitempty"`
	// Dropped counts requests the kernel could not record because its ring
	// buffer was full; changes near a drop are left unattributed, not "kernel".
	Dropped uint64 `json:"dropped,omitempty"`
	// Records is how many requests the sensor has seen since the agent started.
	Records uint64 `json:"records,omitempty"`
}

type NetlinkLink struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	State       string `json:"state,omitempty"`
	Flags       string `json:"flags,omitempty"`
	MasterIndex int    `json:"masterIndex,omitempty"`
}

type NetlinkAddress struct {
	InterfaceIndex int    `json:"interfaceIndex"`
	Interface      string `json:"interface,omitempty"`
	Family         string `json:"family,omitempty"`
	Address        string `json:"address"`
	Scope          int    `json:"scope,omitempty"`
	Flags          int    `json:"flags,omitempty"`
}

type NetlinkRoute struct {
	Family         string `json:"family,omitempty"`
	Destination    string `json:"destination"`
	Gateway        string `json:"gateway,omitempty"`
	Source         string `json:"source,omitempty"`
	InterfaceIndex int    `json:"interfaceIndex,omitempty"`
	Interface      string `json:"interface,omitempty"`
	Table          int    `json:"table,omitempty"`
	Priority       int    `json:"priority,omitempty"`
	Protocol       int    `json:"protocol,omitempty"`
	Scope          int    `json:"scope,omitempty"`
	Type           int    `json:"type,omitempty"`
}

type NetlinkNeighbor struct {
	Family         string `json:"family,omitempty"`
	Address        string `json:"address"`
	MAC            string `json:"mac,omitempty"`
	InterfaceIndex int    `json:"interfaceIndex,omitempty"`
	Interface      string `json:"interface,omitempty"`
	State          string `json:"state,omitempty"`
	Flags          int    `json:"flags,omitempty"`
}

// NetlinkCounts is the size of the full kernel state, before any cap.
type NetlinkCounts struct {
	Links     int `json:"links"`
	Addresses int `json:"addresses"`
	Routes    int `json:"routes"`
	Neighbors int `json:"neighbors"`
}

// NetlinkSnapshot is the full kernel state at one moment. Each list is sorted
// and capped; Truncated says how many entries were cut so a reader can tell a
// complete list from a bounded one.
type NetlinkSnapshot struct {
	ResyncedAt time.Time         `json:"resyncedAt"`
	Links      []NetlinkLink     `json:"links,omitempty"`
	Addresses  []NetlinkAddress  `json:"addresses,omitempty"`
	Routes     []NetlinkRoute    `json:"routes,omitempty"`
	Neighbors  []NetlinkNeighbor `json:"neighbors,omitempty"`
	Truncated  NetlinkCounts     `json:"truncated"`
}

// NetlinkReport is one agent's read-only host-network control-plane view. It
// never represents desired state or authorizes a route/link/neighbor mutation.
// A nil report means the recorder is off; Unavailable means it tried and could
// not start.
type NetlinkReport struct {
	Available   bool   `json:"available"`
	Unavailable string `json:"unavailable,omitempty"`
	// Error lists sensor faults that did not stop the recorder (a subscription
	// that is being re-established, a failed periodic snapshot).
	Error string `json:"error,omitempty"`
	Epoch int64  `json:"epoch,omitempty"`
	// Sequence is the newest event the recorder has seen; Cursor is the last
	// event this report carries. Cursor < Sequence means more are pending.
	Sequence uint64 `json:"sequence"`
	Cursor   uint64 `json:"cursor"`
	// Dropped counts events overwritten in the agent ring. Missed is the subset
	// overwritten before this agent could deliver them. Overruns counts kernel
	// receive-buffer overflows (ENOBUFS); Resubscribes counts subscriptions the
	// recorder had to re-establish. Suppressed counts neighbor state churn that
	// was deliberately not recorded. All are cumulative since the agent started.
	Dropped      uint64 `json:"dropped"`
	Missed       uint64 `json:"missed,omitempty"`
	Overruns     uint64 `json:"overruns,omitempty"`
	Resubscribes uint64 `json:"resubscribes,omitempty"`
	Suppressed   uint64 `json:"suppressed,omitempty"`
	// Totals is the cumulative event count per kind, a small fixed vocabulary.
	Totals map[string]uint64 `json:"totals,omitempty"`
	// Generation increments when the kernel state changes between snapshots.
	Generation uint64        `json:"generation"`
	ResyncedAt time.Time     `json:"resyncedAt,omitzero"`
	Counts     NetlinkCounts `json:"counts"`
	// Snapshot is shipped only when Generation changed since the last delivered
	// report (and periodically as a refresh); the controller carries the last
	// one forward, so nil here does not mean "empty".
	Snapshot *NetlinkSnapshot `json:"snapshot,omitempty"`
	Events   []NetlinkEvent   `json:"events,omitempty"`
	// Actor is the requester-attribution sensor's state (bpf/netra_rtnl.c): nil
	// when it is off, Unavailable when it could not start.
	Actor *NetlinkActorStatus `json:"actor,omitempty"`
}

// NetlinkFinding is one evidence-backed observation derived from the recorded
// changes. It is level-triggered: it is reported only while the latest snapshot
// still shows the problem, so it clears itself when the network recovers. It
// states what changed, not why; nothing here is a causal claim.
type NetlinkFinding struct {
	Severity string `json:"severity"` // critical|warning|info
	Kind     string `json:"kind"`
	Node     string `json:"node"`
	// Subject is the node, never an interface or address: interfaces churn per
	// pod, and the alert de-duplication key is built from it.
	Subject       string    `json:"subject"`
	Message       string    `json:"message"`
	Value         float64   `json:"value,omitempty"`
	FirstObserved time.Time `json:"firstObserved"`
	LastObserved  time.Time `json:"lastObserved"`
	// Evidence is the newest few underlying events, newest first. Neighbor
	// events carry MAC addresses, so this stays in the authenticated API and is
	// never copied into an alert, SIEM record or AI brief.
	Evidence []NetlinkEvent `json:"evidence,omitempty"`
}

// NetlinkFindingsResponse is GET /api/v1/netlink/findings.
type NetlinkFindingsResponse struct {
	ObservedAt time.Time `json:"observedAt"`
	Window     string    `json:"window"`
	// Evaluated is the number of fresh nodes whose recorder was read; Skipped
	// counts the rest (stale, recorder off, or unavailable), so "no findings"
	// cannot be mistaken for "nothing was looked at".
	Evaluated int              `json:"evaluated"`
	Skipped   int              `json:"skipped"`
	Findings  []NetlinkFinding `json:"findings"`
}
