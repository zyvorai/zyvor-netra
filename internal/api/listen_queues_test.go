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

func lqAgent(node string, stale bool, q *models.ListenQueueSummary) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, ListenQueues: q}, Stale: stale}
}

func lqEntry(port uint16, queue, max uint32, peak uint32) models.ListenQueueEntry {
	return models.ListenQueueEntry{Family: "ipv4", Addr: "0.0.0.0", Port: port, Queue: queue, Max: max, Peak: peak, PeakPct: int(peak * 100 / (max + 1))}
}

func lqSummary(listeners, full, sat int, syn uint64, buckets map[string]uint64, top ...models.ListenQueueEntry) *models.ListenQueueSummary {
	return &models.ListenQueueSummary{Listeners: listeners, Full: full, Saturated: sat, SynRecv: syn, Samples: 10, Buckets: buckets, Top: top}
}

func TestListenQueueAggregateMergesFreshNodesAndExplainsTheRest(t *testing.T) {
	agents := []models.AgentStatus{
		lqAgent("b", false, lqSummary(10, 1, 2, 4, map[string]uint64{"empty": 90, "full": 3}, lqEntry(443, 2, 1, 2))),
		lqAgent("a", false, lqSummary(5, 0, 1, 1, map[string]uint64{"empty": 40, "le_75": 2}, lqEntry(80, 4, 9, 6))),
		lqAgent("old-agent", false, nil),
		lqAgent("blind", false, &models.ListenQueueSummary{Unavailable: "netlink refused"}),
		lqAgent("gone", true, lqSummary(999, 999, 999, 999, map[string]uint64{"full": 999})), // stale: not counted
	}
	v := aggregateListenQueues(agents, 10)
	if v.Reporting != 2 || v.NotReporting != 2 {
		t.Fatalf("reporting=%d notReporting=%d, want 2 and 2", v.Reporting, v.NotReporting)
	}
	if v.Listeners != 15 || v.Full != 1 || v.Saturated != 3 || v.SynRecv != 5 {
		t.Fatalf("totals = listeners %d full %d saturated %d synRecv %d", v.Listeners, v.Full, v.Saturated, v.SynRecv)
	}
	if v.Buckets["empty"] != 130 || v.Buckets["full"] != 3 || v.Buckets["le_75"] != 2 {
		t.Fatalf("buckets = %v", v.Buckets)
	}
	if len(v.Top) != 2 || v.Top[0].Node != "b" || v.Top[0].Port != 443 || v.Top[1].Node != "a" {
		t.Fatalf("top = %+v, want the full :443 (100%%) ahead of :80 (40%%)", v.Top)
	}
	for _, n := range v.Nodes {
		if n.Node == "blind" && (n.Reporting || n.Unavailable != "netlink refused") {
			t.Fatalf("the reason a node is not reporting must be surfaced: %+v", n)
		}
		if n.Node == "old-agent" && (n.Reporting || n.Unavailable != "") {
			t.Fatalf("a node with no summary is not reporting and has no reason: %+v", n)
		}
	}
	if len(v.Nodes) != 4 || v.Nodes[0].Node != "a" {
		t.Fatalf("nodes = %+v, want 4 sorted by name (stale excluded)", v.Nodes)
	}
}

func TestListenQueueTopIsBoundedAndOrderedByFillNotByRawDepth(t *testing.T) {
	// :1 holds 90 of a 1000 backlog (9%); :2 holds 2 of a backlog of 1 (full).
	// Raw depth would put :1 first; the listener that is refusing must lead.
	v := aggregateListenQueues([]models.AgentStatus{
		lqAgent("a", false, lqSummary(2, 1, 1, 0, nil, lqEntry(1, 90, 1000, 90), lqEntry(2, 2, 1, 2), lqEntry(3, 1, 9, 1))),
	}, 2)
	if len(v.Top) != 2 || v.Top[0].Port != 2 || v.Top[1].Port != 3 {
		t.Fatalf("top = %+v, want [:2 (full), :3 (10%%)] bounded to 2", v.Top)
	}
}

func lqServer(t *testing.T, query string, agents ...models.AgentReport) *httptest.ResponseRecorder {
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
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/listen-queues"+query, nil))
	return rec
}

func TestListenQueuesEndpointFiltersByNodeAndBoundsTop(t *testing.T) {
	rec := lqServer(t, "?top=1&node=n1",
		models.AgentReport{Node: "n1", ListenQueues: lqSummary(3, 1, 1, 0, nil, lqEntry(1, 2, 1, 2), lqEntry(2, 1, 9, 1))},
		models.AgentReport{Node: "n2", ListenQueues: lqSummary(50, 9, 9, 0, nil, lqEntry(9, 2, 1, 2))},
	)
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var v listenQueuesView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Nodes) != 1 || v.Listeners != 3 || len(v.Top) != 1 {
		t.Fatalf("view = %+v: ?node=n1 must exclude n2 and ?top=1 bound the list", v)
	}
}

func TestListenQueueMetricsAreBoundedAggregates(t *testing.T) {
	rec := httptest.NewRecorder()
	writeListenQueueMetrics(rec, []models.AgentStatus{
		lqAgent("a", false, lqSummary(4, 1, 2, 3, map[string]uint64{"empty": 7, "full": 1}, lqEntry(8080, 2, 1, 2))),
		lqAgent("b", false, lqSummary(6, 0, 0, 2, map[string]uint64{"empty": 5})),
		lqAgent("c", false, nil),
	})
	out := rec.Body.String()
	for _, want := range []string{
		"netra_listen_queue_nodes_reporting 2", "netra_listen_queue_nodes_not_reporting 1",
		"netra_listen_queue_listeners 10", "netra_listen_queue_full_listeners 1",
		"netra_listen_queue_saturated_listeners 2", "netra_listen_queue_syn_recv 5",
		`netra_listen_queue_fill_samples{bucket="empty"} 12`, `netra_listen_queue_fill_samples{bucket="full"} 1`,
		`netra_listen_queue_fill_samples{bucket="le_50"} 0`, // every bin is always present
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "netra_listen_queue_fill_samples{"); n != 6 {
		t.Errorf("%d histogram series, want exactly the 6 fixed bins", n)
	}
	if strings.Contains(out, "8080") || strings.Contains(out, "0.0.0.0") {
		t.Fatalf("a port or address leaked into metrics:\n%s", out)
	}
}

func TestListenQueueMetricsWhenNoNodeReportsSayWhyValuesAreAbsent(t *testing.T) {
	rec := httptest.NewRecorder()
	writeListenQueueMetrics(rec, []models.AgentStatus{lqAgent("a", false, &models.ListenQueueSummary{Unavailable: "x"})})
	out := rec.Body.String()
	if !strings.Contains(out, "netra_listen_queue_nodes_reporting 0") || !strings.Contains(out, "netra_listen_queue_nodes_not_reporting 1") {
		t.Fatalf("coverage gauges missing:\n%s", out)
	}
	if strings.Contains(out, "netra_listen_queue_listeners") {
		t.Fatalf("values must be absent, not zero, when no node samples:\n%s", out)
	}
}

func TestListenQueuesRouteNeedsOnlyViewer(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/listen-queues", nil)
	req.Pattern = "GET /api/v1/listen-queues"
	if got := requiredRole(req); got.String() != "viewer" {
		t.Fatalf("needs %s, want viewer", got)
	}
}
