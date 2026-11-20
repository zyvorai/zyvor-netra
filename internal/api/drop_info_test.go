// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func dropAgent(node string, stale bool, d *models.DropInfoSummary) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, DropInfo: d}, Stale: stale}
}

func dropFlow(src string, sport, dport uint16, reason string, n uint64) models.DropInfoFlow {
	return models.DropInfoFlow{Family: "ipv4", Proto: "tcp", Src: src, Dst: "10.9.9.9", SrcPort: sport, DstPort: dport, Reason: reason, Count: n, Location: "nf_hook_slow"}
}

func dropSummary(drops uint64, reasons map[string]uint64, flows ...models.DropInfoFlow) *models.DropInfoSummary {
	var sites []models.DropInfoSite
	for r, c := range reasons {
		sites = append(sites, models.DropInfoSite{Reason: r, Location: "nf_hook_slow", Count: c})
	}
	return &models.DropInfoSummary{
		Attached: true,
		Totals:   models.DropInfoTotals{Drops: drops, WithTuple: drops - 1, NoTuple: 1},
		Reasons:  reasons, Sites: sites, Flows: flows,
	}
}

func TestDropAggregateMergesFreshNodesAndExplainsTheOnesWithoutTheSensor(t *testing.T) {
	agents := []models.AgentStatus{
		dropAgent("b", false, dropSummary(10, map[string]uint64{"NETFILTER_DROP": 8, "NO_SOCKET": 2}, dropFlow("10.0.0.2", 40000, 443, "NETFILTER_DROP", 8))),
		dropAgent("a", false, dropSummary(5, map[string]uint64{"NETFILTER_DROP": 5}, dropFlow("10.0.0.1", 40001, 443, "NETFILTER_DROP", 3), dropFlow("10.0.0.1", 40002, 80, "NETFILTER_DROP", 2))),
		dropAgent("old-agent", false, nil),
		dropAgent("nobtf", false, &models.DropInfoSummary{Unavailable: "kernel BTF not available"}),
		dropAgent("gone", true, dropSummary(1000, map[string]uint64{"X": 1000})), // stale: must not count
	}
	v := aggregateDropInfo(agents, 10, "")
	if v.Reporting != 2 || v.NotReporting != 2 {
		t.Fatalf("reporting=%d notReporting=%d, want 2 and 2 (stale nodes are not listed at all)", v.Reporting, v.NotReporting)
	}
	if v.Totals.Drops != 15 || v.Totals.NoTuple != 2 {
		t.Fatalf("totals = %+v", v.Totals)
	}
	if len(v.Reasons) != 2 || v.Reasons[0].Reason != "NETFILTER_DROP" || v.Reasons[0].Count != 13 || v.Reasons[1].Count != 2 {
		t.Fatalf("reasons = %+v, want merged and busiest first", v.Reasons)
	}
	// Sites merge across nodes.
	if len(v.Sites) != 2 || v.Sites[0].Count != 13 {
		t.Fatalf("sites = %+v", v.Sites)
	}
	if v.Flows[0].Node != "b" || v.Flows[0].Count != 8 || v.Flows[1].Node != "a" || v.Flows[1].SrcPort != 40001 {
		t.Fatalf("flows = %+v, want busiest first, tagged with their node", v.Flows)
	}
	for _, n := range v.Nodes {
		if n.Node == "nobtf" && (n.Reporting || !strings.Contains(n.Unavailable, "BTF")) {
			t.Fatalf("the reason a node is not reporting must be surfaced: %+v", n)
		}
		if n.Node == "old-agent" && (n.Reporting || n.Unavailable != "") {
			t.Fatalf("a node with no DropInfo is not reporting and has no reason: %+v", n)
		}
	}
	if len(v.Nodes) != 4 || v.Nodes[0].Node != "a" {
		t.Fatalf("nodes = %+v, want 4 sorted by name", v.Nodes)
	}
}

func TestDropAggregateReasonFilterAppliesToFlowsAndSitesOnly(t *testing.T) {
	d := dropSummary(10, map[string]uint64{"NETFILTER_DROP": 8, "NO_SOCKET": 2},
		dropFlow("10.0.0.1", 1, 443, "NETFILTER_DROP", 8), dropFlow("10.0.0.1", 2, 53, "NO_SOCKET", 2))
	v := aggregateDropInfo([]models.AgentStatus{dropAgent("a", false, d)}, 10, "NO_SOCKET")
	if len(v.Flows) != 1 || v.Flows[0].Reason != "NO_SOCKET" {
		t.Fatalf("flows = %+v", v.Flows)
	}
	if len(v.Sites) != 1 || v.Sites[0].Reason != "NO_SOCKET" {
		t.Fatalf("sites = %+v", v.Sites)
	}
	if v.Totals.Drops != 10 || len(v.Reasons) != 2 {
		t.Fatalf("totals and the per-reason breakdown must stay whole so the filter is not misread: %+v %+v", v.Totals, v.Reasons)
	}
}

func TestDropAggregateTopBoundsFlowsAndSites(t *testing.T) {
	var fl []models.DropInfoFlow
	reasons := map[string]uint64{}
	for i := range 30 {
		fl = append(fl, dropFlow("10.0.0.1", uint16(40000+i), 443, "NETFILTER_DROP", uint64(i+1)))
		reasons[fmt.Sprintf("R%02d", i)] = uint64(i + 1)
	}
	v := aggregateDropInfo([]models.AgentStatus{dropAgent("a", false, dropSummary(500, reasons, fl...))}, 5, "")
	if len(v.Flows) != 5 || v.Flows[0].Count != 30 || len(v.Sites) != 5 {
		t.Fatalf("flows=%d sites=%d, want the top 5 of each, busiest first", len(v.Flows), len(v.Sites))
	}
}

func dropInfoServer(t *testing.T, query string, agents ...models.AgentReport) *httptest.ResponseRecorder {
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
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/ebpf/drop-info"+query, nil))
	return rec
}

func TestDropInfoEndpointFiltersByNodeReasonAndBoundsTop(t *testing.T) {
	var fl []models.DropInfoFlow
	for i := range 10 {
		fl = append(fl, dropFlow("10.0.0.1", uint16(41000+i), 443, "NETFILTER_DROP", uint64(i+1)))
	}
	rec := dropInfoServer(t, "?top=3&node=n1&reason=NETFILTER_DROP",
		models.AgentReport{Node: "n1", DropInfo: dropSummary(55, map[string]uint64{"NETFILTER_DROP": 55}, fl...)},
		models.AgentReport{Node: "n2", DropInfo: dropSummary(999, map[string]uint64{"NETFILTER_DROP": 999})},
	)
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var v dropInfoView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Nodes) != 1 || v.Nodes[0].Node != "n1" || v.Totals.Drops != 55 {
		t.Fatalf("view = %+v: ?node=n1 must exclude n2", v)
	}
	if len(v.Flows) != 3 {
		t.Fatalf("flows = %d, want ?top=3", len(v.Flows))
	}
}

func TestDropInfoMetricsAreBoundedAggregates(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDropInfoMetrics(rec, []models.AgentStatus{
		dropAgent("a", false, dropSummary(4, map[string]uint64{"NETFILTER_DROP": 3, "NO_SOCKET": 1}, dropFlow("10.0.0.1", 40000, 443, "NETFILTER_DROP", 3))),
		dropAgent("b", false, dropSummary(6, map[string]uint64{"NETFILTER_DROP": 6})),
		dropAgent("c", false, nil),
	})
	out := rec.Body.String()
	for _, want := range []string{
		"netra_drop_info_nodes_reporting 2", "netra_drop_info_nodes_not_reporting 1",
		"netra_drop_info_drops 10", "netra_drop_info_drops_without_tuple 2",
		`netra_drop_info_reason_drops{reason="NETFILTER_DROP"} 9`, `netra_drop_info_reason_drops{reason="NO_SOCKET"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Cardinality: neither tuples nor kernel functions become labels.
	for _, leak := range []string{"10.0.0.1", "40000", "nf_hook_slow"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q leaked into metrics:\n%s", leak, out)
		}
	}
}

func TestDropInfoMetricReasonSeriesAreCappedWithAnOtherBucket(t *testing.T) {
	reasons := map[string]uint64{}
	var total uint64
	for i := range maxDropReasonSeries + 10 {
		reasons[fmt.Sprintf("R%03d", i)] = uint64(1000 - i)
		total += uint64(1000 - i)
	}
	rec := httptest.NewRecorder()
	writeDropInfoMetrics(rec, []models.AgentStatus{dropAgent("a", false, dropSummary(total, reasons))})
	out := rec.Body.String()
	if n := strings.Count(out, "netra_drop_info_reason_drops{"); n != maxDropReasonSeries+1 {
		t.Fatalf("%d reason series, want %d plus one other bucket", n, maxDropReasonSeries)
	}
	var other uint64
	for i := maxDropReasonSeries; i < maxDropReasonSeries+10; i++ {
		other += uint64(1000 - i)
	}
	if want := fmt.Sprintf(`netra_drop_info_reason_drops{reason="other"} %d`, other); !strings.Contains(out, want) {
		t.Fatalf("missing %q (the folded reasons must still be counted) in:\n%s", want, out)
	}
}

func TestDropInfoMetricsWhenNoNodeReportsSayWhyCountersAreAbsent(t *testing.T) {
	rec := httptest.NewRecorder()
	writeDropInfoMetrics(rec, []models.AgentStatus{dropAgent("a", false, &models.DropInfoSummary{Unavailable: "no BTF"})})
	out := rec.Body.String()
	if !strings.Contains(out, "netra_drop_info_nodes_reporting 0") || !strings.Contains(out, "netra_drop_info_nodes_not_reporting 1") {
		t.Fatalf("coverage gauges missing:\n%s", out)
	}
	if strings.Contains(out, "netra_drop_info_drops ") {
		t.Fatalf("counters must be absent, not zero, when no node runs the sensor:\n%s", out)
	}
}

func TestDropInfoRouteNeedsOnlyViewer(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/ebpf/drop-info", nil)
	req.Pattern = "GET /api/v1/ebpf/drop-info"
	if got := requiredRole(req); got.String() != "viewer" {
		t.Fatalf("needs %s, want viewer", got)
	}
}
