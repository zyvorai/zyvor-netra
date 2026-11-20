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

func l7Agent(node string, stale bool, q *models.L7SampleSummary) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, L7Sample: q}, Stale: stale}
}

func l7Summary(eligible, emitted uint64, protos ...models.L7SampleProtocol) *models.L7SampleSummary {
	s := &models.L7SampleSummary{Attached: true, Ports: []string{"6379:redis"}, Eligible: eligible, Emitted: emitted, Protocols: protos}
	if emitted > 0 {
		s.ScaleFactor = float64(eligible) / float64(emitted)
	}
	return s
}

func redisProto(gets, sets, resp, errs uint64) models.L7SampleProtocol {
	return models.L7SampleProtocol{
		Protocol: "redis", Role: "served", Requests: gets + sets, Responses: resp, Errors: errs,
		Ops:   []models.L7SampleOp{{Op: "GET", Count: gets}, {Op: "SET", Count: sets}},
		Codes: []models.L7SampleCode{{Code: "ERR", Status: "error", Count: errs}},
	}
}

func TestL7AggregateMergesNodesAndScalesEachByItsOwnRatio(t *testing.T) {
	agents := []models.AgentStatus{
		l7Agent("a", false, l7Summary(1000, 10, redisProto(8, 2, 10, 1))),  // scale 100
		l7Agent("b", false, l7Summary(100, 50, redisProto(20, 30, 50, 4))), // scale 2
		l7Agent("off", false, nil),
		l7Agent("broken", false, &models.L7SampleSummary{Unavailable: "could not load"}),
		l7Agent("gone", true, l7Summary(1, 1, redisProto(999, 999, 999, 999))), // stale: not counted
	}
	v := aggregateL7Sample(agents, "")
	if v.Reporting != 2 || v.NotReporting != 2 || v.Eligible != 1100 || v.Emitted != 60 {
		t.Fatalf("view = %+v", v)
	}
	if len(v.Protocols) != 1 {
		t.Fatalf("protocols = %+v", v.Protocols)
	}
	p := v.Protocols[0]
	if p.Requests != 60 || p.Responses != 60 || p.Errors != 5 {
		t.Fatalf("redis = %+v", p)
	}
	// Each node scales by its own ratio: 10*100 + 50*2 = 1100 requests estimated.
	if p.EstRequests != 1100 {
		t.Fatalf("estimated requests = %v, want 1100 (10x100 from a, 50x2 from b)", p.EstRequests)
	}
	byOp := map[string]l7SampleOpAgg{}
	for _, o := range p.Ops {
		byOp[o.Op] = o
	}
	// SET (2+30) outranks GET (8+20); each is scaled node by node.
	if p.Ops[0].Op != "SET" || byOp["GET"].Count != 28 || byOp["GET"].Estimated != 8*100+20*2 || byOp["SET"].Estimated != 2*100+30*2 {
		t.Fatalf("ops = %+v", p.Ops)
	}
	for _, n := range v.Nodes {
		if n.Node == "broken" && (n.Reporting || n.Unavailable != "could not load") {
			t.Fatalf("the reason a node is not reporting must be surfaced: %+v", n)
		}
	}
	if len(v.Nodes) != 4 || v.Nodes[0].Node != "a" {
		t.Fatalf("nodes = %+v", v.Nodes)
	}
}

func TestL7AggregateProtocolFilterAndUnsampledNodes(t *testing.T) {
	pg := models.L7SampleProtocol{Protocol: "postgres", Role: "served", Requests: 5, Ops: []models.L7SampleOp{{Op: "SELECT", Count: 5}}}
	v := aggregateL7Sample([]models.AgentStatus{l7Agent("a", false, l7Summary(0, 0, redisProto(1, 1, 2, 0), pg))}, "postgres")
	if len(v.Protocols) != 1 || v.Protocols[0].Protocol != "postgres" {
		t.Fatalf("filter = %+v", v.Protocols)
	}
	// Nothing emitted yet: counts are raw, never multiplied by zero.
	if v.Protocols[0].EstRequests != 5 || v.ScaleFactor != 0 {
		t.Fatalf("est=%v scale=%v: with no scale factor the raw count is reported", v.Protocols[0].EstRequests, v.ScaleFactor)
	}
}

func TestL7AggregateBoundsOperationsPerProtocol(t *testing.T) {
	var ops []models.L7SampleOp
	for i := 0; i < 80; i++ {
		ops = append(ops, models.L7SampleOp{Op: fmt.Sprintf("/pkg.Svc/M%02d", i), Count: uint64(100 - i)})
	}
	v := aggregateL7Sample([]models.AgentStatus{l7Agent("a", false, l7Summary(10, 10, models.L7SampleProtocol{Protocol: "http2", Role: "served", Requests: 5000, Ops: ops}))}, "")
	got := v.Protocols[0].Ops
	if len(got) != maxAggOps+1 || got[len(got)-1].Op != "OTHER" {
		t.Fatalf("%d ops, last %q; want %d plus an OTHER bucket", len(got), got[len(got)-1].Op, maxAggOps)
	}
	var total uint64
	for _, o := range got {
		total += o.Count
	}
	var want uint64
	for _, o := range ops {
		want += o.Count
	}
	if total != want {
		t.Fatalf("folding into OTHER lost counts: %d vs %d", total, want)
	}
}

func TestL7SampledEndpointFiltersByNodeAndProtocol(t *testing.T) {
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_AGENT_KEY", "")
	t.Setenv("NETRA_METRICS_TOKEN", "")
	st := store.New()
	for _, r := range []models.AgentReport{
		{Node: "n1", L7Sample: l7Summary(10, 10, redisProto(3, 1, 4, 0))},
		{Node: "n2", L7Sample: l7Summary(10, 10, redisProto(90, 9, 99, 0))},
	} {
		r.ObservedAt = time.Now().UTC()
		st.Report(r)
	}
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/l7/sampled?node=n1&protocol=redis", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var v l7SampleView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Nodes) != 1 || v.Nodes[0].Node != "n1" || len(v.Protocols) != 1 || v.Protocols[0].Requests != 4 {
		t.Fatalf("view = %+v: ?node=n1 must exclude n2", v)
	}
}

func TestL7SampleMetricsAreBoundedAndCarryNoPayloadDerivedText(t *testing.T) {
	rec := httptest.NewRecorder()
	writeL7SampleMetrics(rec, []models.AgentStatus{
		l7Agent("a", false, l7Summary(200, 2, redisProto(8, 2, 10, 3),
			models.L7SampleProtocol{Protocol: "http2", Role: "served", Requests: 4, Responses: 4, Undecodable: 2, Ops: []models.L7SampleOp{{Op: "/pkg.Svc/Method", Count: 4}}})),
		l7Agent("b", false, nil),
	})
	out := rec.Body.String()
	for _, want := range []string{
		"netra_l7_sample_nodes_reporting 1", "netra_l7_sample_nodes_not_reporting 1", "netra_l7_sample_scale_factor 100",
		`netra_l7_sample_requests{protocol="redis",role="served",op="GET"} 8`, `netra_l7_sample_requests{protocol="http2",role="served",op="/pkg.Svc/Method"} 4`,
		`netra_l7_sample_responses{protocol="redis",role="served",status="error"} 3`, `netra_l7_sample_responses{protocol="redis",role="served",status="ok"} 7`,
		`netra_l7_sample_error_codes{protocol="redis",role="served",code="ERR"} 3`, `netra_l7_sample_undecodable{protocol="http2",role="served"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "host=") || strings.Contains(out, "node=") {
		t.Fatalf("a host or node became a label:\n%s", out)
	}
}

func TestL7SampleMetricsAreAbsentWhenNoNodeSamples(t *testing.T) {
	rec := httptest.NewRecorder()
	writeL7SampleMetrics(rec, []models.AgentStatus{l7Agent("a", false, nil), l7Agent("b", false, &models.L7SampleSummary{Unavailable: "x"})})
	out := rec.Body.String()
	if !strings.Contains(out, "netra_l7_sample_nodes_reporting 0") || strings.Contains(out, "netra_l7_sample_requests") {
		t.Fatalf("with no sampling node only the coverage gauges may appear:\n%s", out)
	}
}

func TestL7SampledRouteNeedsOnlyViewer(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/l7/sampled", nil)
	req.Pattern = "GET /api/v1/l7/sampled"
	if got := requiredRole(req); got.String() != "viewer" {
		t.Fatalf("needs %s, want viewer", got)
	}
}

// The same request is observed in two roles (leaving its client, arriving at its
// server). They must stay separate rows so nobody adds them into one number.
func TestL7AggregateKeepsServedAndIssuedApart(t *testing.T) {
	served := redisProto(10, 0, 10, 0)
	issued := redisProto(10, 0, 10, 0)
	issued.Role = "issued"
	v := aggregateL7Sample([]models.AgentStatus{l7Agent("a", false, l7Summary(20, 20, served, issued))}, "redis")
	if len(v.Protocols) != 2 || v.Protocols[0].Role != "issued" || v.Protocols[1].Role != "served" {
		t.Fatalf("protocols = %+v, want one row per role", v.Protocols)
	}
	for _, p := range v.Protocols {
		if p.Requests != 10 {
			t.Fatalf("%s requests = %d, want 10 (not 20 from adding the roles)", p.Role, p.Requests)
		}
	}
	rec := httptest.NewRecorder()
	writeL7SampleMetrics(rec, []models.AgentStatus{l7Agent("a", false, l7Summary(20, 20, served, issued))})
	for _, want := range []string{`role="served",op="GET"} 10`, `role="issued",op="GET"} 10`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
