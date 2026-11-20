// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package netlinkdiag turns the host network changes the netlink recorder keeps
// (internal/netlinkwatch, docs/netlink-recorder.md) into evidence-backed
// findings: the default route was removed, the default gateway stopped
// answering, a host uplink went down or was deleted, an uplink's MTU changed,
// or the recorder itself lost changes.
//
// The shape is the one every other health-signal package uses (capdrift,
// pathdiag, dropdiag): Build(agents, ...) returns findings, and Anomalies
// converts them to models.NetworkHealthAnomaly so they reach the alert poller,
// incidents, the AI brief and the SIEM export through internal/health.
//
// Findings are level-triggered. A change is only a finding while the latest full
// snapshot still shows the problem, so a finding clears itself when the network
// recovers, and a transient state between two snapshots is not reported until a
// snapshot confirms it. That is what keeps pod churn (a veth created and
// deleted, a neighbor that resolves a second later) from alerting. Thresholds are
// conservative heuristics, not statistical claims, and a finding says what
// changed, never why.
package netlinkdiag

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// DefaultWindow is how far back a change can still be a finding.
	DefaultWindow = 15 * time.Minute

	// confirmWithin is how long a fresh neighbor or link change waits for a
	// snapshot to confirm it before it is reported on the event alone. Snapshots
	// are taken every 30 s, so this covers one full cycle plus slack.
	confirmWithin = 45 * time.Second

	mainTable   = 254
	maxEvidence = 5
	maxListed   = 3

	// A single failed neighbor is routine in Kubernetes (a pod died and a
	// cached entry expired); several at once on one node is a pattern.
	neighborPatternMin = 3
)

// Finding kinds. All are node-level, so a finding's Subject is the node.
const (
	KindDefaultRouteRemoved = "netlink-default-route-removed"
	KindGatewayUnreachable  = "netlink-gateway-unreachable"
	KindNeighborFailed      = "netlink-neighbor-failed"
	KindLinkDown            = "netlink-link-down"
	KindLinkDeleted         = "netlink-link-deleted"
	KindMTUChanged          = "netlink-mtu-changed"
	KindOverrun             = "netlink-overrun"
)

// hostLinkTypes are the link types treated as host uplinks. Pod veths, tunnel
// endpoints and bridges are excluded on purpose: veths appear and disappear
// with every pod, and bridges such as libvirt's virbr0 toggle carrier as guests
// start and stop. Alerting on those would be alerting on normal operation.
var hostLinkTypes = map[string]bool{"device": true, "bond": true, "team": true, "vlan": true}

var downStates = map[string]bool{"down": true, "lower-layer-down": true, "not-present": true}

// Build evaluates every fresh agent's recorded changes. now is explicit so the
// result is a pure function of its inputs.
func Build(agents []models.AgentStatus, now time.Time, window time.Duration) models.NetlinkFindingsResponse {
	if window <= 0 {
		window = DefaultWindow
	}
	resp := models.NetlinkFindingsResponse{ObservedAt: now.UTC(), Window: window.String(), Findings: []models.NetlinkFinding{}}
	for _, a := range agents {
		n := a.Netlink
		if a.Stale || n == nil || !n.Available {
			resp.Skipped++
			continue
		}
		resp.Evaluated++
		resp.Findings = append(resp.Findings, evaluate(a.Node, n, now, window)...)
	}
	rank := map[string]int{"critical": 3, "warning": 2, "info": 1}
	sort.SliceStable(resp.Findings, func(i, j int) bool {
		a, b := resp.Findings[i], resp.Findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] > rank[b.Severity]
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Kind < b.Kind
	})
	return resp
}

// Anomalies converts findings to the shared health-anomaly shape. Messages carry
// interface names and IP addresses, never MAC addresses; the evidence, which
// does, stays on the Finding.
func Anomalies(findings []models.NetlinkFinding) []models.NetworkHealthAnomaly {
	out := make([]models.NetworkHealthAnomaly, 0, len(findings))
	for _, f := range findings {
		out = append(out, models.NetworkHealthAnomaly{
			Severity: f.Severity, Kind: f.Kind, Subject: f.Subject,
			SourceKey: "node:" + f.Node, Message: f.Message, Value: f.Value,
		})
	}
	return out
}

// nodeView is one node's recorded state, prepared once per evaluation.
type nodeView struct {
	node   string
	now    time.Time
	since  time.Time
	window time.Duration
	all    []models.NetlinkEvent // every retained event, chronological
	in     []models.NetlinkEvent // the ones inside the window
	snap   *models.NetlinkSnapshot
}

func evaluate(node string, n *models.NetlinkReport, now time.Time, window time.Duration) []models.NetlinkFinding {
	v := nodeView{node: node, now: now, since: now.Add(-window), window: window, snap: n.Snapshot}
	v.all = append([]models.NetlinkEvent(nil), n.Events...)
	sort.SliceStable(v.all, func(i, j int) bool { return v.all[i].ObservedAt.Before(v.all[j].ObservedAt) })
	for _, e := range v.all {
		if !e.ObservedAt.Before(v.since) && !e.ObservedAt.After(now.Add(time.Minute)) {
			v.in = append(v.in, e)
		}
	}
	var out []models.NetlinkFinding
	out = append(out, v.defaultRoutes()...)
	out = append(out, v.neighbors()...)
	out = append(out, v.links()...)
	out = append(out, v.mtu()...)
	out = append(out, v.overruns()...)
	return out
}

type verdict int

const (
	// useSnapshot: a snapshot was taken after the change, so it decides.
	useSnapshot verdict = iota
	// pending: too recent for any snapshot to have seen it yet.
	pending
	// eventOnly: the snapshot is missing or old, and the event is old enough
	// that waiting longer would hide a real problem.
	eventOnly
)

func (v nodeView) judge(at time.Time) verdict {
	if v.snap != nil && !v.snap.ResyncedAt.Before(at) {
		return useSnapshot
	}
	if v.now.Sub(at) < confirmWithin {
		return pending
	}
	return eventOnly
}

func (v nodeView) finding(sev, kind, msg string, value float64, ev []models.NetlinkEvent) models.NetlinkFinding {
	sorted := append([]models.NetlinkEvent(nil), ev...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ObservedAt.After(sorted[j].ObservedAt) })
	f := models.NetlinkFinding{Severity: sev, Kind: kind, Node: v.node, Subject: v.node, Message: msg, Value: value}
	if len(sorted) > 0 {
		f.LastObserved = sorted[0].ObservedAt
		f.FirstObserved = sorted[len(sorted)-1].ObservedAt
	}
	if len(sorted) > maxEvidence {
		sorted = sorted[:maxEvidence]
	}
	f.Evidence = sorted
	return f
}

func isDefault(e models.NetlinkEvent) bool {
	return e.Kind == models.NetlinkKindRoute && e.Destination == "default" && e.Table == mainTable
}

// hasDefault reports whether the snapshot holds a usable default route for the
// family in the main table. Blackhole and unreachable defaults do not count.
func hasDefault(s *models.NetlinkSnapshot, family string) bool {
	for _, r := range s.Routes {
		if r.Destination == "default" && r.Table == mainTable && r.Family == family && (r.Type == 0 || r.Type == 1) {
			return true
		}
	}
	return false
}

// defaultGateways are the next hops of the snapshot's main-table default routes.
func defaultGateways(s *models.NetlinkSnapshot) map[string]bool {
	out := map[string]bool{}
	if s == nil {
		return out
	}
	for _, r := range s.Routes {
		if r.Destination == "default" && r.Table == mainTable && r.Gateway != "" {
			out[r.Gateway] = true
		}
	}
	return out
}

func (v nodeView) defaultRoutes() []models.NetlinkFinding {
	var out []models.NetlinkFinding
	for _, fam := range []string{"ipv4", "ipv6"} {
		var last *models.NetlinkEvent
		var deletes []models.NetlinkEvent
		for i := range v.in {
			e := v.in[i]
			if !isDefault(e) || e.Family != fam {
				continue
			}
			last = &v.in[i]
			if e.Action == "delete" {
				deletes = append(deletes, e)
			}
		}
		// A later add (a replace, or a re-add after a flap) means it is back.
		if last == nil || last.Action != "delete" {
			continue
		}
		// A removal is never worth waiting on: report it on the event alone
		// unless a snapshot taken afterwards shows a default route again.
		if v.judge(last.ObservedAt) == useSnapshot && v.snap != nil && hasDefault(v.snap, fam) {
			continue
		}
		sev, name := "critical", "IPv4"
		if fam == "ipv6" {
			sev, name = "warning", "IPv6"
		}
		msg := fmt.Sprintf("%s default route%s was removed from the main table%s and none remains", name, viaDetail(*last), who(*last))
		out = append(out, v.finding(sev, KindDefaultRouteRemoved, msg, 1, deletes))
	}
	return out
}

func viaDetail(e models.NetlinkEvent) string {
	switch {
	case e.Gateway != "" && e.Interface != "":
		return fmt.Sprintf(" (via %s on %s)", e.Gateway, e.Interface)
	case e.Interface != "":
		return fmt.Sprintf(" (on %s)", e.Interface)
	case e.Gateway != "":
		return fmt.Sprintf(" (via %s)", e.Gateway)
	}
	return ""
}

// who says who asked for a change, when the attribution sensor could tell. It is
// empty when it could not (the sensor is off, unavailable, or dropped requests), so
// a message never claims more than was known. The requester is a join by message
// type, interface and time: "probable" is stated as such, and several matching
// requesters are listed as alternatives, never picked between.
func who(e models.NetlinkEvent) string {
	switch e.Origin {
	case models.NetlinkOriginKernel:
		return " by the kernel (no process requested it)"
	case models.NetlinkOriginProcess:
		a := e.Actor
		if a == nil {
			return ""
		}
		if a.Confidence == models.NetlinkActorAmbiguous {
			return fmt.Sprintf(" by one of %s (ambiguous: %d requesters at that moment)", strings.Join(a.Alternatives, ", "), a.Candidates)
		}
		detail := fmt.Sprintf("pid %d", a.PID)
		if a.Pod != "" {
			detail += fmt.Sprintf(", pod %s/%s", a.Namespace, a.Pod)
		}
		return fmt.Sprintf(" by %s (%s)", a.Comm, detail)
	}
	return ""
}

// whoAll is who() for a finding built from several events: named only when they
// all agree, since one sentence cannot honestly attribute a mix.
func whoAll(ev []models.NetlinkEvent) string {
	if len(ev) == 0 {
		return ""
	}
	first := who(ev[0])
	for _, e := range ev[1:] {
		if who(e) != first {
			return ""
		}
	}
	return first
}

func (v nodeView) neighbors() []models.NetlinkFinding {
	type key struct {
		idx  int
		addr string
	}
	lastFor := map[key]models.NetlinkEvent{}
	for _, e := range v.in {
		if e.Kind != models.NetlinkKindNeighbor {
			continue
		}
		k := key{e.InterfaceIndex, e.Address}
		if e.Action == "delete" {
			delete(lastFor, k)
			continue
		}
		lastFor[k] = e
	}
	gateways := defaultGateways(v.snap)
	var gw, other []models.NetlinkEvent
	for k, e := range lastFor {
		// Only FAILED: the kernel gave up resolving it. INCOMPLETE is the normal
		// transient while ARP/NDP is in flight and would alert on every new peer.
		if !strings.Contains(e.State, "failed") {
			continue
		}
		switch v.judge(e.ObservedAt) {
		case pending:
			continue
		case useSnapshot:
			if !v.snapshotHasFailedNeighbor(k.idx, k.addr) {
				continue
			}
		}
		if gateways[e.Address] {
			gw = append(gw, e)
		} else {
			other = append(other, e)
		}
	}
	var out []models.NetlinkFinding
	if len(gw) > 0 {
		names := addrList(gw)
		out = append(out, v.finding("critical", KindGatewayUnreachable,
			fmt.Sprintf("default gateway %s failed ARP/NDP resolution: it is not answering at layer 2", names), float64(len(gw)), gw))
	}
	if len(other) > 0 {
		sev := "info"
		if len(other) >= neighborPatternMin {
			sev = "warning"
		}
		out = append(out, v.finding(sev, KindNeighborFailed,
			fmt.Sprintf("%d neighbor(s) failed ARP/NDP resolution: %s", len(other), addrList(other)), float64(len(other)), other))
	}
	return out
}

func (v nodeView) snapshotHasFailedNeighbor(idx int, addr string) bool {
	for _, n := range v.snap.Neighbors {
		if n.InterfaceIndex == idx && n.Address == addr {
			return strings.Contains(n.State, "failed")
		}
	}
	return false
}

// addrList names up to maxListed addresses, in a stable order, and says how many
// more there were.
func addrList(ev []models.NetlinkEvent) string {
	seen := map[string]bool{}
	var addrs []string
	for _, e := range ev {
		if !seen[e.Address] {
			seen[e.Address] = true
			addrs = append(addrs, e.Address)
		}
	}
	sort.Strings(addrs)
	return listNames(addrs)
}

func listNames(names []string) string {
	if len(names) <= maxListed {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:maxListed], ", "), len(names)-maxListed)
}

func (v nodeView) links() []models.NetlinkFinding {
	last := map[int]models.NetlinkEvent{}
	for _, e := range v.in {
		if e.Kind == models.NetlinkKindLink && hostLinkTypes[e.LinkType] && e.InterfaceIndex > 0 {
			last[e.InterfaceIndex] = e
		}
	}
	// Interfaces that carried a default route: from the snapshot, and from the
	// default routes removed in the window (the kernel drops a link's routes as
	// it goes down, so the snapshot alone would already have lost them).
	carried := map[int]bool{}
	if v.snap != nil {
		for _, r := range v.snap.Routes {
			if r.Destination == "default" && r.Table == mainTable {
				carried[r.InterfaceIndex] = true
			}
		}
	}
	for _, e := range v.in {
		if isDefault(e) && e.Action == "delete" {
			carried[e.InterfaceIndex] = true
		}
	}

	var down, deleted []models.NetlinkEvent
	critical := false
	for idx, e := range last {
		wasDeleted := e.Action == "delete"
		if !wasDeleted && !downStates[e.State] {
			continue // its last recorded state is up
		}
		switch v.judge(e.ObservedAt) {
		case pending:
			continue
		case useSnapshot:
			cur, found := v.snapLink(idx, e.Interface)
			if wasDeleted && found {
				continue // it exists again
			}
			if !wasDeleted && (!found || !downStates[cur.State]) {
				continue // it came back up, or it is gone and reported as deleted
			}
		}
		if wasDeleted {
			deleted = append(deleted, e)
			continue
		}
		down = append(down, e)
		if carried[idx] {
			critical = true
		}
	}
	var out []models.NetlinkFinding
	if len(down) > 0 {
		sev := "warning"
		if critical {
			sev = "critical"
		}
		out = append(out, v.finding(sev, KindLinkDown,
			fmt.Sprintf("host link(s) went down: %s%s", linkList(down, true), whoAll(down)), float64(len(down)), down))
	}
	if len(deleted) > 0 {
		out = append(out, v.finding("warning", KindLinkDeleted,
			fmt.Sprintf("host link(s) were deleted: %s%s", linkList(deleted, false), whoAll(deleted)), float64(len(deleted)), deleted))
	}
	return out
}

// snapLink finds a link by index, or by name if the index was reused.
func (v nodeView) snapLink(idx int, name string) (models.NetlinkLink, bool) {
	if v.snap == nil {
		return models.NetlinkLink{}, false
	}
	for _, l := range v.snap.Links {
		if l.Index == idx || (name != "" && l.Name == name) {
			return l, true
		}
	}
	return models.NetlinkLink{}, false
}

func linkList(ev []models.NetlinkEvent, withState bool) string {
	var names []string
	for _, e := range ev {
		n := e.Interface
		if n == "" {
			n = fmt.Sprintf("ifindex %d", e.InterfaceIndex)
		}
		if withState {
			n += " (" + e.State + ")"
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return listNames(names)
}

// mtu reports a host uplink whose MTU at the end of the window differs from what
// it was before it. A change and a change back inside the window is no change.
func (v nodeView) mtu() []models.NetlinkFinding {
	type span struct {
		name                string
		before, after, prev int
		events              []models.NetlinkEvent
	}
	byIdx := map[int]*span{}
	for _, e := range v.all {
		if e.Kind != models.NetlinkKindLink || !hostLinkTypes[e.LinkType] || e.MTU <= 0 || e.InterfaceIndex <= 0 {
			continue
		}
		s := byIdx[e.InterfaceIndex]
		if s == nil {
			s = &span{}
			byIdx[e.InterfaceIndex] = s
		}
		if e.Interface != "" {
			s.name = e.Interface
		}
		if e.ObservedAt.Before(v.since) {
			s.before, s.prev = e.MTU, e.MTU
			continue
		}
		// Inside the window: every value that differs from the one before it is a change.
		if s.prev != 0 && e.MTU != s.prev {
			s.events = append(s.events, e)
		}
		s.prev, s.after = e.MTU, e.MTU
	}
	var changed []models.NetlinkEvent
	var descr []string
	for idx, s := range byIdx {
		if s.before == 0 || s.after == 0 || s.before == s.after || len(s.events) == 0 {
			continue
		}
		name := s.name
		if name == "" {
			name = fmt.Sprintf("ifindex %d", idx)
		}
		descr = append(descr, fmt.Sprintf("%s %d to %d", name, s.before, s.after))
		changed = append(changed, s.events...)
	}
	if len(descr) == 0 {
		return nil
	}
	sort.Strings(descr)
	return []models.NetlinkFinding{v.finding("warning", KindMTUChanged,
		fmt.Sprintf("host link MTU changed: %s%s", listNames(descr), whoAll(changed)), float64(len(descr)), changed)}
}

// overruns says the recorder itself lost changes, so a quiet timeline in the
// same period is not evidence that nothing happened.
func (v nodeView) overruns() []models.NetlinkFinding {
	var lost []models.NetlinkEvent
	overflow := 0
	for _, e := range v.in {
		if e.Kind != models.NetlinkKindOverrun {
			continue
		}
		lost = append(lost, e)
		if strings.Contains(strings.ToLower(e.Detail), "no buffer space") {
			overflow++
		}
	}
	if len(lost) == 0 {
		return nil
	}
	sev := "info"
	if overflow > 0 {
		sev = "warning"
	}
	return []models.NetlinkFinding{v.finding(sev, KindOverrun,
		fmt.Sprintf("the netlink recorder lost kernel messages %d time(s) in the last %s (%d receive-buffer overflows): network changes in those gaps were not recorded, and the next snapshot resync restores current state only",
			len(lost), v.window, overflow), float64(len(lost)), lost)}
}
