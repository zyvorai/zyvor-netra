// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/netlinkdiag"
)

const (
	netlinkDefaultSince = time.Hour
	netlinkDefaultLimit = 500
	netlinkMaxLimit     = 5000
)

// netlinkKinds is the fixed event vocabulary: it validates ?kind= and is the
// only label set /metrics ever uses for netlink.
var netlinkKinds = []string{
	models.NetlinkKindLink, models.NetlinkKindAddress, models.NetlinkKindRoute,
	models.NetlinkKindNeighbor, models.NetlinkKindOverrun,
}

// netlinkNodeState is one node's recorder health and, on request, its full
// kernel snapshot.
type netlinkNodeState struct {
	Node           string               `json:"node"`
	ObservedAt     time.Time            `json:"observedAt"`
	Stale          bool                 `json:"stale"`
	Reporting      bool                 `json:"reporting"`
	AgentStartedAt time.Time            `json:"agentStartedAt,omitzero"`
	Unavailable    string               `json:"unavailable,omitempty"`
	Error          string               `json:"error,omitempty"`
	Epoch          int64                `json:"epoch,omitempty"`
	Sequence       uint64               `json:"sequence"`
	Dropped        uint64               `json:"dropped"`
	Missed         uint64               `json:"missed"`
	Overruns       uint64               `json:"overruns"`
	Resubscribes   uint64               `json:"resubscribes"`
	Suppressed     uint64               `json:"suppressed"`
	Totals         map[string]uint64    `json:"totals,omitempty"`
	Generation     uint64               `json:"generation"`
	ResyncedAt     time.Time            `json:"resyncedAt,omitzero"`
	Counts         models.NetlinkCounts `json:"counts"`
	// HistorySince is the earliest event the controller holds for this node.
	// Changes before it (an agent restart, or a controller restart) are a blind
	// spot, not a quiet period.
	HistorySince time.Time               `json:"historySince,omitzero"`
	Snapshot     *models.NetlinkSnapshot `json:"snapshot,omitempty"`
	// Actor is the requester-attribution sensor's state: nil when it is off.
	Actor *models.NetlinkActorStatus `json:"actor,omitempty"`
}

// netlinkChanges serves GET /api/v1/netlink?view=events|state|all&node=&kind=&since=&limit=.
// It is deliberately read-only: there is no route that changes a link, address,
// route or neighbor.
func (s *Server) netlinkChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	node := strings.TrimSpace(q.Get("node"))
	kind := strings.ToLower(strings.TrimSpace(q.Get("kind")))
	if kind != "" && !slices.Contains(netlinkKinds, kind) {
		errorJSON(w, http.StatusBadRequest, "kind must be one of "+strings.Join(netlinkKinds, ", "))
		return
	}
	view := strings.ToLower(strings.TrimSpace(q.Get("view")))
	switch view {
	case "":
		view = "events"
	case "events", "state", "all":
	default:
		errorJSON(w, http.StatusBadRequest, "view must be events, state or all")
		return
	}
	limit := netlinkDefaultLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > netlinkMaxLimit {
			errorJSON(w, http.StatusBadRequest, fmt.Sprintf("limit must be 1-%d", netlinkMaxLimit))
			return
		}
		limit = n
	}
	now := time.Now()
	since := now.Add(-netlinkDefaultSince)
	if raw := strings.TrimSpace(q.Get("since")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			since = now.Add(-d)
		} else if at, err := time.Parse(time.RFC3339, raw); err == nil {
			since = at
		} else {
			errorJSON(w, http.StatusBadRequest, "since must be a duration such as 30m or an RFC3339 timestamp")
			return
		}
	}

	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	if node != "" {
		agents = slices.DeleteFunc(agents, func(a models.AgentStatus) bool { return a.Node != node })
	}
	states := netlinkStates(agents, view != "events")
	out := map[string]any{"observedAt": now.UTC(), "view": view, "nodes": states}
	if view != "state" {
		out["events"] = netlinkEvents(agents, kind, since, limit)
		out["since"] = since.UTC()
		out["limit"] = limit
	}
	writeJSON(w, http.StatusOK, out)
}

// netlinkFindings serves GET /api/v1/netlink/findings?window=15m&node=NAME: the
// evidence-backed findings derived from the recorded changes (internal/netlinkdiag).
// They are level-triggered, so the list is what is wrong now, not everything that
// ever changed; Skipped counts nodes that could not be evaluated.
func (s *Server) netlinkFindings(w http.ResponseWriter, r *http.Request) {
	window := netlinkdiag.DefaultWindow
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			errorJSON(w, http.StatusBadRequest, "window must be a duration between 1m and 24h, such as 15m")
			return
		}
		window = d
	}
	now := time.Now()
	agents := s.store.AgentStatuses(now, s.agentStaleAfter)
	if node := strings.TrimSpace(r.URL.Query().Get("node")); node != "" {
		agents = slices.DeleteFunc(agents, func(a models.AgentStatus) bool { return a.Node != node })
	}
	writeJSON(w, http.StatusOK, netlinkdiag.Build(agents, now, window))
}

func netlinkStates(agents []models.AgentStatus, withSnapshot bool) []netlinkNodeState {
	out := make([]netlinkNodeState, 0, len(agents))
	for _, a := range agents {
		st := netlinkNodeState{Node: a.Node, ObservedAt: a.ObservedAt, Stale: a.Stale, AgentStartedAt: a.AgentStartedAt}
		n := a.Netlink
		switch {
		case n == nil:
			st.Unavailable = "recorder off (NETRA_NETLINK=off) or agent predates the recorder"
		case !n.Available:
			st.Unavailable = n.Unavailable
		default:
			st.Reporting = true
			st.Error, st.Epoch, st.Sequence = n.Error, n.Epoch, n.Sequence
			st.Dropped, st.Missed, st.Overruns = n.Dropped, n.Missed, n.Overruns
			st.Resubscribes, st.Suppressed, st.Totals = n.Resubscribes, n.Suppressed, n.Totals
			st.Generation, st.ResyncedAt, st.Counts = n.Generation, n.ResyncedAt, n.Counts
			st.Actor = n.Actor
			if len(n.Events) > 0 {
				st.HistorySince = n.Events[0].ObservedAt
			}
			if withSnapshot {
				st.Snapshot = n.Snapshot
			}
		}
		out = append(out, st)
	}
	return out
}

// netlinkEvents merges every node's retained changes into one time-ordered
// timeline, newest `limit` entries.
func netlinkEvents(agents []models.AgentStatus, kind string, since time.Time, limit int) []models.NetlinkEvent {
	events := make([]models.NetlinkEvent, 0)
	for _, a := range agents {
		if a.Netlink == nil {
			continue
		}
		for _, e := range a.Netlink.Events {
			if e.ObservedAt.Before(since) || (kind != "" && e.Kind != kind) {
				continue
			}
			e.Node = a.Node
			events = append(events, e)
		}
	}
	slices.SortStableFunc(events, func(a, b models.NetlinkEvent) int {
		if c := a.ObservedAt.Compare(b.ObservedAt); c != 0 {
			return c
		}
		if a.Node != b.Node {
			return strings.Compare(a.Node, b.Node)
		}
		if a.Epoch != b.Epoch {
			if a.Epoch < b.Epoch {
				return -1
			}
			return 1
		}
		switch {
		case a.Sequence < b.Sequence:
			return -1
		case a.Sequence > b.Sequence:
			return 1
		}
		return 0
	})
	if len(events) > limit {
		events = slices.Clone(events[len(events)-limit:])
	}
	return events
}

// netlinkTotals is the cluster-wide view of the fresh, reporting nodes.
type netlinkTotals struct {
	Reporting, NotReporting                             int
	Events                                              map[string]uint64
	Dropped, Missed, Overruns, Resubscribes, Suppressed uint64
	Counts                                              models.NetlinkCounts
}

func aggregateNetlink(agents []models.AgentStatus) netlinkTotals {
	t := netlinkTotals{Events: map[string]uint64{}}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := a.Netlink
		if n == nil || !n.Available {
			t.NotReporting++
			continue
		}
		t.Reporting++
		for k, v := range n.Totals {
			t.Events[k] += v
		}
		t.Dropped += n.Dropped
		t.Missed += n.Missed
		t.Overruns += n.Overruns
		t.Resubscribes += n.Resubscribes
		t.Suppressed += n.Suppressed
		t.Counts.Links += n.Counts.Links
		t.Counts.Addresses += n.Counts.Addresses
		t.Counts.Routes += n.Counts.Routes
		t.Counts.Neighbors += n.Counts.Neighbors
	}
	return t
}

// writeNetlinkMetrics adds recorder gauges to /metrics. Like every agent-derived
// cumulative count here they are gauges of the sum over fresh nodes (a counter
// would go backwards when an agent restarts or a node goes stale). The only
// label is the event kind, a fixed five-value set: interface names, addresses
// and MACs stay in the JSON API.
func writeNetlinkMetrics(w http.ResponseWriter, agents []models.AgentStatus) {
	t := aggregateNetlink(agents)
	metricGauge(w, "netra_netlink_nodes_reporting", "Fresh node agents recording host network control-plane changes over netlink.", float64(t.Reporting))
	metricGauge(w, "netra_netlink_nodes_not_reporting", "Fresh node agents not recording netlink changes (off, older agent, or the recorder could not start).", float64(t.NotReporting))
	if t.Reporting == 0 {
		return
	}
	fmt.Fprint(w, "# HELP netra_netlink_events Link, address, route and neighbor changes recorded since each agent started, summed across nodes. kind=overrun counts lost subscriptions, not network changes.\n# TYPE netra_netlink_events gauge\n")
	for _, k := range netlinkKinds {
		fmt.Fprintf(w, "netra_netlink_events{kind=\"%s\"} %d\n", k, t.Events[k])
	}
	metricGauge(w, "netra_netlink_dropped_events", "Recorded changes overwritten in the agents' bounded rings. Non-zero means a node changed faster than the ring holds.", float64(t.Dropped))
	metricGauge(w, "netra_netlink_missed_events", "Recorded changes overwritten before an agent could deliver them: a real gap in the timeline.", float64(t.Missed))
	metricGauge(w, "netra_netlink_overruns", "Kernel netlink receive-buffer overflows (ENOBUFS). Each one means changes were lost until the next snapshot resync.", float64(t.Overruns))
	metricGauge(w, "netra_netlink_resubscribes", "Netlink subscriptions the agents had to re-establish.", float64(t.Resubscribes))
	metricGauge(w, "netra_netlink_suppressed_neighbor_events", "Routine neighbor state churn (reachable/stale/delay/probe) counted but not recorded.", float64(t.Suppressed))
	metricGauge(w, "netra_netlink_links", "Network links on reporting nodes at their latest snapshot.", float64(t.Counts.Links))
	metricGauge(w, "netra_netlink_addresses", "Interface addresses on reporting nodes at their latest snapshot.", float64(t.Counts.Addresses))
	metricGauge(w, "netra_netlink_routes", "Routes (all tables) on reporting nodes at their latest snapshot.", float64(t.Counts.Routes))
	metricGauge(w, "netra_netlink_neighbors", "ARP/NDP neighbor entries on reporting nodes at their latest snapshot.", float64(t.Counts.Neighbors))
	bySeverity := map[string]int{}
	for _, f := range netlinkdiag.Build(agents, time.Now(), netlinkdiag.DefaultWindow).Findings {
		bySeverity[f.Severity]++
	}
	fmt.Fprint(w, "# HELP netra_netlink_findings Active host-network findings (default route removed, gateway unreachable, uplink down or deleted, MTU changed, recorder overrun) by severity. Level-triggered: they clear when the network recovers.\n# TYPE netra_netlink_findings gauge\n")
	for _, sev := range []string{"critical", "warning", "info"} {
		fmt.Fprintf(w, "netra_netlink_findings{severity=\"%s\"} %d\n", sev, bySeverity[sev])
	}
}
