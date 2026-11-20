// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func nlEvent(seq uint64, kind, action string, at time.Time) models.NetlinkEvent {
	return models.NetlinkEvent{Epoch: 1, Sequence: seq, Kind: kind, Action: action, ObservedAt: at}
}

func nlServer(now time.Time) *Server {
	st := store.New()
	snap := &models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 1, Name: "lo"}}}
	st.Report(models.AgentReport{Node: "worker-1", ObservedAt: now, Netlink: &models.NetlinkReport{
		Available: true, Epoch: 1, Sequence: 3, Cursor: 3, Snapshot: snap,
		Counts: models.NetlinkCounts{Links: 1}, Overruns: 1, Totals: map[string]uint64{"route": 2, "link": 1},
		Events: []models.NetlinkEvent{
			nlEvent(1, "route", "delete", now.Add(-2*time.Hour)),
			nlEvent(2, "route", "new", now.Add(-10*time.Minute)),
			nlEvent(3, "link", "new", now.Add(-5*time.Minute)),
		},
	}})
	st.Report(models.AgentReport{Node: "worker-2", ObservedAt: now, Netlink: &models.NetlinkReport{
		Available: true, Epoch: 9, Sequence: 1, Cursor: 1,
		Events: []models.NetlinkEvent{nlEvent(1, "neighbor", "new", now.Add(-time.Minute))},
	}})
	st.Report(models.AgentReport{Node: "off-node", ObservedAt: now})
	return &Server{store: st, agentStaleAfter: time.Minute}
}

func nlGet(t *testing.T, s *Server, query string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.netlinkChanges(rec, httptest.NewRequest("GET", "/api/v1/netlink"+query, nil))
	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("bad json: %v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func TestNetlinkEventsAreTimeOrderedFilteredAndCrossNode(t *testing.T) {
	now := time.Now().UTC()
	s := nlServer(now)
	code, body := nlGet(t, s, "?since=30m")
	if code != 200 {
		t.Fatalf("status=%d", code)
	}
	ev := body["events"].([]any)
	// The two-hour-old route delete is outside since=30m; the rest interleave by time.
	if len(ev) != 3 {
		t.Fatalf("events=%v", ev)
	}
	first := ev[0].(map[string]any)
	last := ev[2].(map[string]any)
	if first["kind"] != "route" || first["node"] != "worker-1" || last["kind"] != "neighbor" || last["node"] != "worker-2" {
		t.Fatalf("not time-ordered with node attribution: %v", ev)
	}
	_, body = nlGet(t, s, "?since=3h&kind=route")
	if got := len(body["events"].([]any)); got != 2 {
		t.Fatalf("kind filter: %d events", got)
	}
	_, body = nlGet(t, s, "?since=3h&limit=1")
	if got := body["events"].([]any); len(got) != 1 || got[0].(map[string]any)["kind"] != "neighbor" {
		t.Fatalf("limit must keep the newest: %v", got)
	}
	_, body = nlGet(t, s, "?since=3h&node=worker-2")
	if got := len(body["events"].([]any)); got != 1 {
		t.Fatalf("node filter: %d", got)
	}
}

func TestNetlinkViewsAndNodeStates(t *testing.T) {
	s := nlServer(time.Now().UTC())
	_, body := nlGet(t, s, "")
	nodes := body["nodes"].([]any)
	if len(nodes) != 3 {
		t.Fatalf("nodes=%v", nodes)
	}
	byName := map[string]map[string]any{}
	for _, n := range nodes {
		m := n.(map[string]any)
		byName[m["node"].(string)] = m
	}
	if byName["worker-1"]["reporting"] != true || byName["worker-1"]["overruns"].(float64) != 1 {
		t.Fatalf("worker-1=%v", byName["worker-1"])
	}
	if _, has := byName["worker-1"]["snapshot"]; has {
		t.Fatal("the default view must not ship every node's full snapshot")
	}
	if byName["off-node"]["reporting"] != false || byName["off-node"]["unavailable"] == "" {
		t.Fatalf("a node without the recorder must say so: %v", byName["off-node"])
	}
	if byName["worker-1"]["historySince"] == nil {
		t.Fatal("historySince (the blind-spot edge) missing")
	}

	_, state := nlGet(t, s, "?view=state")
	if _, has := state["events"]; has {
		t.Fatal("view=state must not include events")
	}
	for _, n := range state["nodes"].([]any) {
		m := n.(map[string]any)
		if m["node"] == "worker-1" && m["snapshot"] == nil {
			t.Fatal("view=state must include the snapshot")
		}
	}
	_, all := nlGet(t, s, "?view=all")
	if all["events"] == nil {
		t.Fatal("view=all must include events")
	}
}

func TestNetlinkRejectsBadInput(t *testing.T) {
	s := nlServer(time.Now().UTC())
	for _, q := range []string{"?kind=bogus", "?view=bogus", "?limit=0", "?limit=99999", "?limit=x", "?since=yesterday"} {
		if code, _ := nlGet(t, s, q); code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", q, code)
		}
	}
	if code, _ := nlGet(t, s, "?since=2026-09-21T10:00:00Z&kind=ROUTE"); code != 200 {
		t.Errorf("RFC3339 since and an upper-case kind must be accepted: %d", code)
	}
}

func TestNetlinkAggregateAndMetricsUseFreshReportingNodesOnly(t *testing.T) {
	agents := []models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "a", Netlink: &models.NetlinkReport{
			Available: true, Overruns: 2, Dropped: 5, Suppressed: 7, Resubscribes: 2,
			Totals: map[string]uint64{"route": 10, "overrun": 2}, Counts: models.NetlinkCounts{Links: 3, Routes: 40},
		}}},
		{AgentReport: models.AgentReport{Node: "b", Netlink: &models.NetlinkReport{
			Available: true, Totals: map[string]uint64{"route": 1}, Counts: models.NetlinkCounts{Links: 2},
		}}},
		{AgentReport: models.AgentReport{Node: "old"}},
		{AgentReport: models.AgentReport{Node: "blind", Netlink: &models.NetlinkReport{Unavailable: "no rtnl"}}},
		{AgentReport: models.AgentReport{Node: "gone", Netlink: &models.NetlinkReport{Available: true, Overruns: 999}}, Stale: true},
	}
	v := aggregateNetlink(agents)
	if v.Reporting != 2 || v.NotReporting != 2 || v.Overruns != 2 || v.Events["route"] != 11 || v.Counts.Links != 5 {
		t.Fatalf("aggregate=%+v", v)
	}
	rec := httptest.NewRecorder()
	writeNetlinkMetrics(rec, agents)
	out := rec.Body.String()
	for _, want := range []string{
		"netra_netlink_nodes_reporting 2", "netra_netlink_nodes_not_reporting 2",
		`netra_netlink_events{kind="route"} 11`, `netra_netlink_events{kind="link"} 0`,
		"netra_netlink_overruns 2", "netra_netlink_routes 40",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "999") {
		t.Error("a stale node leaked into the metrics")
	}
	// Cardinality guard: no label other than the fixed kind set.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "netra_netlink") && strings.Contains(line, "{") && !strings.Contains(line, "{kind=") && !strings.Contains(line, "{severity=") {
			t.Errorf("unexpected label on %q", line)
		}
	}
}

func TestNetlinkMetricsAreAbsentNotZeroWhenNothingReports(t *testing.T) {
	rec := httptest.NewRecorder()
	writeNetlinkMetrics(rec, []models.AgentStatus{{AgentReport: models.AgentReport{Node: "old"}}})
	out := rec.Body.String()
	if !strings.Contains(out, "netra_netlink_nodes_not_reporting 1") || strings.Contains(out, "netra_netlink_overruns") {
		t.Fatalf("metrics=%s", out)
	}
}

func nlFindingsServer(now time.Time) *Server {
	st := store.New()
	gone := models.NetlinkEvent{Epoch: 1, Sequence: 1, Kind: "route", Action: "delete", Family: "ipv4", Destination: "default",
		Gateway: "10.0.0.1", Interface: "eth0", Table: 254, ObservedAt: now.Add(-2 * time.Minute)}
	st.Report(models.AgentReport{Node: "worker-1", ObservedAt: now, Netlink: &models.NetlinkReport{
		Available: true, Epoch: 1, Sequence: 1, Cursor: 1, Events: []models.NetlinkEvent{gone}}})
	st.Report(models.AgentReport{Node: "worker-2", ObservedAt: now, Netlink: &models.NetlinkReport{Available: true, Epoch: 2}})
	st.Report(models.AgentReport{Node: "off-node", ObservedAt: now})
	return &Server{store: st, agentStaleAfter: time.Minute}
}

func nlFindingsGet(t *testing.T, s *Server, query string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.netlinkFindings(rec, httptest.NewRequest("GET", "/api/v1/netlink/findings"+query, nil))
	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("bad json: %v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func TestNetlinkFindingsEndpointReportsWhatIsWrongAndWhatWasNotChecked(t *testing.T) {
	s := nlFindingsServer(time.Now().UTC())
	code, body := nlFindingsGet(t, s, "")
	if code != 200 {
		t.Fatalf("status=%d", code)
	}
	fs := body["findings"].([]any)
	if len(fs) != 1 {
		t.Fatalf("findings=%v", fs)
	}
	f := fs[0].(map[string]any)
	if f["kind"] != "netlink-default-route-removed" || f["severity"] != "critical" || f["node"] != "worker-1" || f["subject"] != "worker-1" {
		t.Fatalf("finding=%v", f)
	}
	if len(f["evidence"].([]any)) != 1 {
		t.Fatalf("evidence=%v", f["evidence"])
	}
	// Two nodes recorded, one node has the recorder off: silence is not health.
	if body["evaluated"].(float64) != 2 || body["skipped"].(float64) != 1 || body["window"] != "15m0s" {
		t.Fatalf("evaluated=%v skipped=%v window=%v", body["evaluated"], body["skipped"], body["window"])
	}
}

func TestNetlinkFindingsFiltersByNodeAndValidatesWindow(t *testing.T) {
	s := nlFindingsServer(time.Now().UTC())
	_, body := nlFindingsGet(t, s, "?node=worker-2")
	if got := len(body["findings"].([]any)); got != 0 {
		t.Fatalf("worker-2 has no findings, got %d", got)
	}
	// A window shorter than the change ends the finding.
	_, body = nlFindingsGet(t, s, "?window=1m")
	if got := len(body["findings"].([]any)); got != 0 {
		t.Fatalf("a 1m window should not reach a change from 2m ago, got %d", got)
	}
	for _, q := range []string{"?window=30s", "?window=48h", "?window=soon"} {
		if code, _ := nlFindingsGet(t, s, q); code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", q, code)
		}
	}
}

func TestNetlinkFindingsGaugeCountsBySeverityWithFixedLabels(t *testing.T) {
	now := time.Now().UTC()
	agents := nlFindingsServer(now).store.AgentStatuses(now, time.Minute)
	rec := httptest.NewRecorder()
	writeNetlinkMetrics(rec, agents)
	out := rec.Body.String()
	for _, want := range []string{
		`netra_netlink_findings{severity="critical"} 1`,
		`netra_netlink_findings{severity="warning"} 0`,
		`netra_netlink_findings{severity="info"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func bpfServer(now time.Time) *Server {
	st := store.New()
	st.Report(models.AgentReport{
		Node: "worker-1", ObservedAt: now, Hooks: []string{"tcx-ingress:eth0", "tcx-egress:eth0"}, Interfaces: []string{"eth0"},
		BPFAttach: &models.BPFAttachReport{Available: true, TCXSupported: true, ObservedAt: now, Total: 1, Hash: "h",
			Interfaces: []models.BPFInterfaceAttach{{Name: "eth0", Index: 2, TCXIngress: []models.BPFProgram{{ID: 1, Name: "cil_from_netdev", Owner: "cilium"}}}}},
	})
	st.Report(models.AgentReport{Node: "off-node", ObservedAt: now})
	return &Server{store: st, agentStaleAfter: time.Minute}
}

func TestBPFAttachmentsShowsKernelStateAndDrift(t *testing.T) {
	s := bpfServer(time.Now().UTC())
	rec := httptest.NewRecorder()
	s.bpfAttachments(rec, httptest.NewRequest("GET", "/api/v1/ebpf/attachments", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	nodes := body["nodes"].([]any)
	byName := map[string]map[string]any{}
	for _, n := range nodes {
		m := n.(map[string]any)
		byName[m["node"].(string)] = m
	}
	w1 := byName["worker-1"]
	if w1["reporting"] != true || len(w1["attached"].([]any)) != 1 || len(w1["hooks"].([]any)) != 2 {
		t.Fatalf("worker-1=%v", w1)
	}
	if byName["off-node"]["reporting"] != false || byName["off-node"]["unavailable"] == "" {
		t.Fatalf("a node with the inventory off must say so: %v", byName["off-node"])
	}
	// The agent believes it has Netra's hooks on eth0; the kernel shows only Cilium's.
	fs := body["findings"].([]any)
	if len(fs) != 1 || fs[0].(map[string]any)["kind"] != "bpf-netra-hook-missing" {
		t.Fatalf("findings=%v", fs)
	}
	if body["evaluated"].(float64) != 1 || body["skipped"].(float64) != 1 {
		t.Fatalf("evaluated=%v skipped=%v", body["evaluated"], body["skipped"])
	}
}

func TestBPFAttachmentsFiltersByNode(t *testing.T) {
	s := bpfServer(time.Now().UTC())
	rec := httptest.NewRecorder()
	s.bpfAttachments(rec, httptest.NewRequest("GET", "/api/v1/ebpf/attachments?node=off-node", nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body["nodes"].([]any)) != 1 || len(body["findings"].([]any)) != 0 {
		t.Fatalf("body=%v", body)
	}
}

func TestBPFAttachMetricsAreFixedCardinality(t *testing.T) {
	now := time.Now().UTC()
	agents := bpfServer(now).store.AgentStatuses(now, time.Minute)
	rec := httptest.NewRecorder()
	writeBPFAttachMetrics(rec, agents)
	out := rec.Body.String()
	for _, want := range []string{
		"netra_bpf_attach_nodes_reporting 1", "netra_bpf_attach_nodes_not_reporting 1", "netra_bpf_attach_interfaces 1",
		`netra_bpf_attach_findings{severity="warning"} 1`, `netra_bpf_attach_findings{severity="critical"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "netra_bpf_attach") && strings.Contains(line, "{") && !strings.Contains(line, "{severity=") {
			t.Errorf("unexpected label on %q", line)
		}
	}
	empty := httptest.NewRecorder()
	writeBPFAttachMetrics(empty, []models.AgentStatus{{AgentReport: models.AgentReport{Node: "old"}}})
	if strings.Contains(empty.Body.String(), "netra_bpf_attach_findings") {
		t.Fatal("gauges must be absent, not zero, when nothing reports")
	}
}

func TestNetlinkEventsCarryTheRequesterAndTheSensorStatus(t *testing.T) {
	now := time.Now().UTC()
	st := store.New()
	st.Report(models.AgentReport{Node: "worker-1", ObservedAt: now, Netlink: &models.NetlinkReport{
		Available: true, Epoch: 1, Sequence: 1, Cursor: 1,
		Actor: &models.NetlinkActorStatus{Available: true, Records: 12},
		Events: []models.NetlinkEvent{{
			Epoch: 1, Sequence: 1, Kind: "route", Action: "delete", Destination: "default", ObservedAt: now.Add(-time.Minute),
			Origin: models.NetlinkOriginProcess,
			Actor:  &models.NetlinkActor{Confidence: "probable", Comm: "calico-node", PID: 42, Namespace: "kube-system", Pod: "calico-node-x"},
		}},
	}})
	s := &Server{store: st, agentStaleAfter: time.Minute}
	rec := httptest.NewRecorder()
	s.netlinkChanges(rec, httptest.NewRequest("GET", "/api/v1/netlink?since=10m", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ev := body["events"].([]any)[0].(map[string]any)
	actor := ev["actor"].(map[string]any)
	if ev["origin"] != "process" || actor["comm"] != "calico-node" || actor["pod"] != "calico-node-x" || actor["confidence"] != "probable" {
		t.Fatalf("event=%v", ev)
	}
	node := body["nodes"].([]any)[0].(map[string]any)
	status, ok := node["actor"].(map[string]any)
	if !ok || status["available"] != true || status["records"].(float64) != 12 {
		t.Fatalf("node=%v", node)
	}
}
