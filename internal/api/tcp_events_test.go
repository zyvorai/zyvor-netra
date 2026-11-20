// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func tcpAgent(node string, stale bool, te *models.TCPEventsSummary) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, TCPEvents: te}, Stale: stale}
}

func summary(retrans, rstSent, rstRecv uint64, flows ...models.TCPEventFlow) *models.TCPEventsSummary {
	return &models.TCPEventsSummary{
		Attached: []string{"retransmit", "send_reset", "receive_reset", "state"},
		Totals:   models.TCPEventTotals{Retransmits: retrans, RSTSent: rstSent, RSTReceived: rstRecv, StateTransitions: 10},
		Transitions: []models.TCPStateTransition{
			{From: "SYN_SENT", To: "ESTABLISHED", Count: 5},
			{From: "ESTABLISHED", To: "FIN_WAIT1", Count: 3},
		},
		Flows: flows,
	}
}

func flow(src string, sport, dport uint16, retrans, rst uint64) models.TCPEventFlow {
	return models.TCPEventFlow{Family: "ipv4", Src: src, Dst: "10.9.9.9", SrcPort: sport, DstPort: dport, Retransmits: retrans, RSTReceived: rst}
}

func TestAggregateMergesFreshNodesAndCountsThoseWithoutTheSensor(t *testing.T) {
	agents := []models.AgentStatus{
		tcpAgent("b", false, summary(10, 2, 3, flow("10.0.0.2", 40000, 443, 9, 0))),
		tcpAgent("a", false, summary(5, 1, 0, flow("10.0.0.1", 40001, 443, 1, 4), flow("10.0.0.1", 40002, 80, 0, 0))),
		tcpAgent("no-sensor", false, nil),
		tcpAgent("skipped", false, &models.TCPEventsSummary{Attached: nil, Skipped: map[string]string{"state": "layout unknown"}}),
		tcpAgent("gone", true, summary(1000, 1000, 1000)), // stale: must not count
	}
	v := aggregateTCPEvents(agents, 10)

	if v.Reporting != 2 || v.NotReporting != 2 {
		t.Fatalf("reporting=%d notReporting=%d, want 2 and 2 (stale nodes are not listed at all)", v.Reporting, v.NotReporting)
	}
	if v.Totals.Retransmits != 15 || v.Totals.RSTSent != 3 || v.Totals.RSTReceived != 3 || v.Totals.StateTransitions != 20 {
		t.Fatalf("totals = %+v", v.Totals)
	}
	if len(v.Nodes) != 4 || v.Nodes[0].Node != "a" || v.Nodes[3].Node != "skipped" {
		t.Fatalf("nodes = %+v (sorted by name, stale excluded)", v.Nodes)
	}
	for _, n := range v.Nodes {
		if n.Node == "no-sensor" && n.Reporting {
			t.Fatal("a node with no TCPEvents must be reported as not reporting")
		}
		if n.Node == "skipped" && n.Skipped["state"] == "" {
			t.Fatalf("the reason a sensor is not running must be surfaced: %+v", n)
		}
	}
	if len(v.Transitions) != 2 || v.Transitions[0].Count != 10 || v.Transitions[0].From != "SYN_SENT" {
		t.Fatalf("transitions = %+v, want merged counts sorted busiest first", v.Transitions)
	}
	// Busiest flow first, tagged with its node: 10.0.0.2's 9 retransmits vs 10.0.0.1:40001's 1+4 = 5.
	if v.Flows[0].Node != "b" || v.Flows[0].Retransmits != 9 || v.Flows[1].Node != "a" || v.Flows[1].SrcPort != 40001 {
		t.Fatalf("flows = %+v", v.Flows)
	}
}

func TestAggregateTopFlowsBound(t *testing.T) {
	var fl []models.TCPEventFlow
	for i := range 30 {
		fl = append(fl, flow("10.0.0.1", uint16(40000+i), 443, uint64(i+1), 0))
	}
	v := aggregateTCPEvents([]models.AgentStatus{tcpAgent("a", false, summary(1, 0, 0, fl...))}, 5)
	if len(v.Flows) != 5 || v.Flows[0].Retransmits != 30 {
		t.Fatalf("flows = %d (first has %d), want the top 5 with the busiest first", len(v.Flows), v.Flows[0].Retransmits)
	}
}

func tcpEventsServer(t *testing.T, agents ...models.AgentReport) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_AGENT_KEY", "")
	t.Setenv("NETRA_METRICS_TOKEN", "")
	st := store.New()
	for _, a := range agents {
		a.ObservedAt = time.Now().UTC()
		st.Report(a)
	}
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/ebpf/tcp-events?top=3&node=n1", nil))
	return rec
}

func TestTCPEventsEndpointFiltersByNodeAndBoundsTop(t *testing.T) {
	var fl []models.TCPEventFlow
	for i := range 10 {
		fl = append(fl, flow("10.0.0.1", uint16(41000+i), 443, uint64(i+1), 0))
	}
	rec := tcpEventsServer(t,
		models.AgentReport{Node: "n1", TCPEvents: summary(7, 0, 0, fl...)},
		models.AgentReport{Node: "n2", TCPEvents: summary(100, 0, 0)},
	)
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var v tcpEventsView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Nodes) != 1 || v.Nodes[0].Node != "n1" || v.Totals.Retransmits != 7 {
		t.Fatalf("view = %+v: ?node=n1 must exclude n2", v)
	}
	if len(v.Flows) != 3 {
		t.Fatalf("flows = %d, want ?top=3", len(v.Flows))
	}
}

func TestTCPEventMetricsAreBoundedAggregates(t *testing.T) {
	var sb strings.Builder
	rec := httptest.NewRecorder()
	writeTCPEventMetrics(rec, []models.AgentStatus{
		tcpAgent("a", false, summary(4, 1, 2, flow("10.0.0.1", 40000, 443, 4, 0))),
		tcpAgent("b", false, summary(6, 0, 1)),
		tcpAgent("c", false, nil),
	})
	sb.WriteString(rec.Body.String())
	out := sb.String()
	for _, want := range []string{
		"netra_tcp_events_nodes_reporting 2", "netra_tcp_events_nodes_not_reporting 1",
		"netra_tcp_events_retransmits 10", "netra_tcp_events_rst_sent 1", "netra_tcp_events_rst_received 3",
		`netra_tcp_state_transitions{from="SYN_SENT",to="ESTABLISHED"} 10`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Cardinality: per-flow data never becomes a label.
	if strings.Contains(out, "10.0.0.1") || strings.Contains(out, "40000") {
		t.Fatalf("a flow address or port leaked into metrics:\n%s", out)
	}
}

func TestTCPEventMetricsWhenNoNodeReportsSayWhyCountersAreAbsent(t *testing.T) {
	rec := httptest.NewRecorder()
	writeTCPEventMetrics(rec, []models.AgentStatus{tcpAgent("a", false, nil)})
	out := rec.Body.String()
	if !strings.Contains(out, "netra_tcp_events_nodes_reporting 0") || !strings.Contains(out, "netra_tcp_events_nodes_not_reporting 1") {
		t.Fatalf("coverage gauges missing:\n%s", out)
	}
	if strings.Contains(out, "netra_tcp_events_retransmits") {
		t.Fatalf("counters must not be exported as zero when no node runs the sensor (absent, not 0):\n%s", out)
	}
}

func TestTCPEventsRouteNeedsOnlyViewer(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/ebpf/tcp-events", nil)
	req.Pattern = "GET /api/v1/ebpf/tcp-events"
	if got := requiredRole(req); got.String() != "viewer" {
		t.Fatalf("needs %s, want viewer", got)
	}
}
