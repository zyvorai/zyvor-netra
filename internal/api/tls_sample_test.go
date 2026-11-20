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

func tlsAgent(node string, q *models.TLSSampleSummary) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, TLSSample: q}}
}

func httpProto(role string, gets, resp, errs uint64) models.L7SampleProtocol {
	return models.L7SampleProtocol{
		Protocol: "http1", Role: role, Requests: gets, Responses: resp, Errors: errs,
		Ops:   []models.L7SampleOp{{Op: "GET", Count: gets}},
		Codes: []models.L7SampleCode{{Code: "200", Status: "ok", Count: resp - errs}, {Code: "503", Status: "error", Count: errs}},
	}
}

func tlsSummary(eligible, emitted uint64, protos ...models.L7SampleProtocol) *models.TLSSampleSummary {
	s := &models.TLSSampleSummary{Attached: true, Libraries: []string{"/usr/lib/libssl.so.3"}, Eligible: eligible, Emitted: emitted, Protocols: protos,
		Hosts: []models.L7SampleHost{{Host: "shop.example", Op: "GET", Count: 4}}}
	if emitted > 0 {
		s.ScaleFactor = float64(eligible) / float64(emitted)
	}
	return s
}

func TestTLSAdapterFeedsTheSameAggregationAndKeepsSourcesApart(t *testing.T) {
	agents := []models.AgentStatus{
		tlsAgent("a", tlsSummary(100, 10, httpProto("issued", 10, 10, 2))),
		tlsAgent("off", nil),
		tlsAgent("broken", &models.TLSSampleSummary{Unavailable: "could not load"}),
		// A node with packet-level sampling only must not leak into the TLS view.
		{AgentReport: models.AgentReport{Node: "l7only", L7Sample: l7Summary(50, 5, redisProto(1, 1, 2, 0))}},
	}
	v := aggregateL7Sample(tlsAsL7(agents), "")
	if v.Reporting != 1 || v.NotReporting != 3 || v.Eligible != 100 || v.Emitted != 10 || v.ScaleFactor != 10 {
		t.Fatalf("view = %+v", v)
	}
	if len(v.Protocols) != 1 || v.Protocols[0].Protocol != "http1" || v.Protocols[0].EstRequests != 100 {
		t.Fatalf("protocols = %+v (10 sampled x scale 10 = 100 estimated)", v.Protocols)
	}
	if len(v.Hosts) != 1 || v.Hosts[0].Host != "shop.example" {
		t.Fatalf("hosts = %+v", v.Hosts)
	}
	for _, n := range v.Nodes {
		if n.Node == "broken" && (n.Reporting || n.Unavailable != "could not load") {
			t.Fatalf("the reason must be surfaced: %+v", n)
		}
		if n.Node == "l7only" && n.Reporting {
			t.Fatal("a node with only packet-level sampling was counted as TLS-reporting")
		}
	}
}

func TestTLSEndpointReturnsLibrariesNotPorts(t *testing.T) {
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_AGENT_KEY", "")
	t.Setenv("NETRA_METRICS_TOKEN", "")
	st := store.New()
	for _, r := range []models.AgentReport{
		{Node: "n1", TLSSample: tlsSummary(10, 10, httpProto("served", 3, 3, 0))},
		{Node: "n2", TLSSample: tlsSummary(10, 10, httpProto("served", 90, 90, 0))},
	} {
		r.ObservedAt = time.Now().UTC()
		st.Report(r)
	}
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/l7/tls?node=n1", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var v l7SampleView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Nodes) != 1 || v.Nodes[0].Node != "n1" || len(v.Nodes[0].Libraries) != 1 || len(v.Nodes[0].Ports) != 0 {
		t.Fatalf("nodes = %+v: libraries must be reported as libraries, and ?node=n1 must exclude n2", v.Nodes)
	}
	if len(v.Protocols) != 1 || v.Protocols[0].Requests != 3 {
		t.Fatalf("protocols = %+v", v.Protocols)
	}
}

func TestTLSMetricFamilyIsSeparateAndBounded(t *testing.T) {
	rec := httptest.NewRecorder()
	agents := []models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "a", TLSSample: tlsSummary(200, 2, httpProto("served", 8, 8, 3)),
			L7Sample: l7Summary(20, 2, redisProto(4, 0, 4, 0))}},
	}
	writeTLSSampleMetrics(rec, agents)
	writeL7SampleMetrics(rec, agents)
	out := rec.Body.String()
	for _, want := range []string{
		"netra_tls_sample_nodes_reporting 1", "netra_tls_sample_scale_factor 100",
		`netra_tls_sample_requests{protocol="http1",role="served",op="GET"} 8`,
		`netra_tls_sample_responses{protocol="http1",role="served",status="error"} 3`,
		`netra_tls_sample_error_codes{protocol="http1",role="served",code="503"} 3`,
		// and the packet-level family is untouched
		`netra_l7_sample_requests{protocol="redis",role="served",op="GET"} 4`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Each family declares its own metadata once; nothing is duplicated or crossed.
	for _, fam := range []string{"netra_tls_sample_requests", "netra_l7_sample_requests"} {
		if n := strings.Count(out, "# TYPE "+fam+" gauge"); n != 1 {
			t.Errorf("%s declared %d times", fam, n)
		}
	}
	if strings.Contains(out, `netra_tls_sample_requests{protocol="redis"`) || strings.Contains(out, `netra_l7_sample_requests{protocol="http1"`) {
		t.Fatalf("the two sources bled into each other:\n%s", out)
	}
	for _, leak := range []string{"shop.example", "libssl", "host=", "node="} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q became part of the metrics:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "Sampled TLS plaintext (observed at OpenSSL) requests") {
		t.Errorf("the TLS family's help text should name its source:\n%s", out)
	}
}

func TestTLSMetricsAreAbsentWhenNoNodeSamples(t *testing.T) {
	rec := httptest.NewRecorder()
	writeTLSSampleMetrics(rec, []models.AgentStatus{tlsAgent("a", nil), tlsAgent("b", &models.TLSSampleSummary{Unavailable: "x"})})
	out := rec.Body.String()
	if !strings.Contains(out, "netra_tls_sample_nodes_reporting 0") || strings.Contains(out, "netra_tls_sample_requests") {
		t.Fatalf("with no sampling node only the coverage gauges may appear:\n%s", out)
	}
}

func TestTLSRouteNeedsOnlyViewer(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/l7/tls", nil)
	req.Pattern = "GET /api/v1/l7/tls"
	if got := requiredRole(req); got.String() != "viewer" {
		t.Fatalf("needs %s, want viewer", got)
	}
}
