// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func report(packets uint64, pid uint32, comm string) models.AgentReport {
	return models.AgentReport{
		Node: "n1",
		Stats: []models.DestinationStat{{
			DestinationIP: "10.0.0.8", Port: 3306, Protocol: "TCP", Direction: "egress",
			Packets: packets, Bytes: packets * 10, Namespace: "app", Pod: "api",
			WorkloadName: "api",
		}},
		TCPHealth: []models.TCPHealthStat{{
			RemoteIP: "10.0.0.8", RemotePort: 3306, PID: pid, Comm: comm, Retransmissions: packets / 10,
			SRTTUS: 1500,
		}},
	}
}

func TestIngestDeltasProcessAndClass(t *testing.T) {
	l := NewLimited(48*time.Hour, 100)
	// Relative to now, not a fixed date: Query prunes records older than the retention window against
	// the wall clock, so a hard-coded date turns this test red once it is more than 48 hours old
	// (it did, on 2026-09-20 at 12:00 UTC, and failed every CI run after that).
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	l.Ingest(base, report(100, 42, "mysqld"))
	if l.Len() != 0 {
		t.Fatalf("baseline emitted %d records", l.Len())
	}
	l.Ingest(base.Add(time.Second), report(140, 42, "mysqld"))
	res := l.Query(Query{Limit: 10})
	if res.Matched != 1 {
		t.Fatalf("matched %d", res.Matched)
	}
	rec := res.Records[0]
	if rec.Packets != 40 || rec.Bytes != 400 || rec.AppProtocol != "mysql" || rec.PID != 42 || rec.Comm != "mysqld" {
		t.Fatalf("%+v", rec)
	}
	if rec.Retrans != 4 {
		t.Fatalf("retrans %d", rec.Retrans)
	}
	raw, _ := json.Marshal(rec)
	for _, key := range []string{`"cmdline"`, `"argv"`, `"environ"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("record contains %s", key)
		}
	}
	filtered := l.Query(Query{Pod: "other", Limit: 10})
	if filtered.Matched != 0 {
		t.Fatalf("filter matched %d", filtered.Matched)
	}
}

func TestClassPorts(t *testing.T) {
	cases := []struct {
		port uint16
		want string
	}{
		{3306, "mysql"}, {5432, "postgres"}, {6379, "redis"}, {9092, "kafka"},
		{50051, "grpc"}, {443, "https"}, {80, "http"}, {9, ""},
	}
	for _, c := range cases {
		if got := Class(c.port, "tcp"); got != c.want {
			t.Fatalf("port %d: got %q want %q", c.port, got, c.want)
		}
	}
}

func TestRED(t *testing.T) {
	recs := []Record{
		{Namespace: "app", Pod: "api", Packets: 100, Blocked: 5, SRTTUS: 1000, AppProtocol: "mysql"},
		{Namespace: "app", Pod: "api", Packets: 50, Retrans: 5, SRTTUS: 3000, AppProtocol: "mysql"},
	}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{
		DNSHealth:    []models.DNSHealthStat{{Namespace: "app", Pod: "api", Failures: 2}},
		HTTPMetadata: []models.HTTPMetadataStat{{Namespace: "app", Pod: "api", Requests: 9, Method: "GET", Host: "example"}},
		HTTPStatus:   []models.HTTPStatusStat{{Namespace: "app", Pod: "api", Status: 503, Count: 4}},
	}}}
	got := RED(recs, agents, time.Minute)
	if got.Count != 1 || got.Rows[0].Packets != 150 || got.Rows[0].Errors != 10 {
		t.Fatalf("%+v", got.Rows)
	}
	if got.Rows[0].DNSFailures != 2 || got.Rows[0].HTTPRequests != 9 || got.Rows[0].HTTP5xx != 4 || got.Rows[0].AvgSRTTUS == 0 {
		t.Fatalf("%+v", got.Rows[0])
	}
	if got.Rows[0].RatePerSec != 150.0/60 {
		t.Fatalf("rate %v", got.Rows[0].RatePerSec)
	}
}

func TestREDL7SampleFoldsNodeScoped5xx(t *testing.T) {
	recs := []Record{
		{Node: "n1", Namespace: "", Pod: "", Packets: 10},
	}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{
		Node: "n1",
		L7Sample: &models.L7SampleSummary{
			Attached:    true,
			ScaleFactor: 2,
			Protocols: []models.L7SampleProtocol{{
				Protocol: "http2",
				Role:     "served",
				Codes:    []models.L7SampleCode{{Code: "503", Status: "error", Count: 3}, {Code: "404", Status: "error", Count: 9}},
			}},
		},
	}}}
	got := RED(recs, agents, time.Minute)
	if got.Count != 1 {
		t.Fatalf("count=%d rows=%+v", got.Count, got.Rows)
	}
	// 3 sampled 503 * scale 2 = 6; 404 must not count.
	if got.Rows[0].HTTP5xx != 6 {
		t.Fatalf("http5xx=%d want 6 (scaled sample); row=%+v", got.Rows[0].HTTP5xx, got.Rows[0])
	}
	if !isHTTP5xxCode("503") || isHTTP5xxCode("404") || isHTTP5xxCode("5") || isHTTP5xxCode("abc") {
		t.Fatal("isHTTP5xxCode helpers wrong")
	}
}

func TestTracesLinkCallee(t *testing.T) {
	t0 := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	recs := []Record{
		{ObservedAt: t0, Namespace: "app", Pod: "web", Peer: "10.1.0.5", Port: 8080, Protocol: "tcp", Packets: 3, AppProtocol: "http"},
		{ObservedAt: t0.Add(time.Second), Namespace: "app", Pod: "api", Peer: "10.1.0.9", Port: 5432, Protocol: "tcp", Packets: 1, AppProtocol: "postgres"},
	}
	got := Traces(recs, map[string]PodIP{"10.1.0.5": {Namespace: "app", Name: "api"}})
	if got.Count != 2 {
		t.Fatalf("count %d", got.Count)
	}
	var child Span
	for _, sp := range got.Spans {
		if sp.Pod == "api" {
			child = sp
		}
	}
	if child.ParentID == "" || child.TraceID == child.SpanID {
		t.Fatalf("child not linked: %+v", child)
	}
}

func TestPrune(t *testing.T) {
	l := NewLimited(time.Minute, 2)
	base := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	l.Ingest(base, report(1, 0, ""))
	l.Ingest(base.Add(time.Second), report(2, 0, ""))
	l.Ingest(base.Add(2*time.Second), report(3, 0, ""))
	l.Ingest(base.Add(3*time.Second), report(4, 0, ""))
	if l.Len() != 2 {
		t.Fatalf("len %d", l.Len())
	}
}
