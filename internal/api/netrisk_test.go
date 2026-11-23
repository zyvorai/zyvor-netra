// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flooddetect"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/tsdb"
)

func ws(ctx, dim, units string, from, to int64, fn func(ts int64) float64) metricstream.WireSeries {
	w := metricstream.WireSeries{Series: tsdb.Series{Context: ctx, Chart: ctx, Dimension: dim, Units: units}}
	for ts := from; ts <= to; ts++ {
		w.Points = append(w.Points, [3]float64{float64(ts), fn(ts), 0})
	}
	return w
}

func TestCapacityForecastEndpoint(t *testing.T) {
	s, h := metricsTestServer(t)
	now := time.Now().Unix()
	from := now - 1800
	rising := ws("netfilter.conntrack_utilization", "used", "%", from, now, func(ts int64) float64 { return 40 + float64(ts-from)*0.02 })
	flat := ws("netfilter.conntrack_utilization", "used", "%", from, now, func(int64) float64 { return 20 })
	if _, err := s.metricsHub.Ingest(&metricstream.Batch{Node: "n1", To: now, Series: []metricstream.WireSeries{rising}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.metricsHub.Ingest(&metricstream.Batch{Node: "n2", To: now, Series: []metricstream.WireSeries{flat}}); err != nil {
		t.Fatal(err)
	}
	code, body := authedGet(t, h, "/api/v1/capacity/forecast?window=30m")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	fc := body["forecasts"].([]any)
	if len(fc) != 2 {
		t.Fatalf("forecasts %v", fc)
	}
	first := fc[0].(map[string]any)
	if first["node"] != "n1" || first["resource"] != "conntrack" || first["secondsToExhaustion"] == nil {
		t.Fatalf("worst first: %v", first)
	}
	if first["severity"] == "ok" {
		t.Fatalf("a rising table must not be ok: %v", first)
	}
	gaps := strings.Join(toStrings(body["gaps"]), "|")
	if !strings.Contains(gaps, "ephemeral-ports") {
		t.Fatalf("missing ephemeral series should be reported as a gap: %v", body["gaps"])
	}
	if len(body["caveats"].([]any)) == 0 {
		t.Fatal("caveats")
	}
	code, body = authedGet(t, h, "/api/v1/capacity/forecast?node=n2")
	if code != http.StatusOK || len(body["forecasts"].([]any)) != 1 {
		t.Fatalf("node filter: %d %v", code, body)
	}
	for _, bad := range []string{"?window=abc", "?window=1s", "?window=999h", "?window=-5m"} {
		if code, _ := authedGet(t, h, "/api/v1/capacity/forecast"+bad); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, code)
		}
	}
}

func TestCapacityForecastRequiresMetrics(t *testing.T) {
	s, h := metricsTestServer(t)
	s.metricsHub = nil
	if code, _ := authedGet(t, h, "/api/v1/capacity/forecast"); code != http.StatusServiceUnavailable {
		t.Fatalf("%d", code)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestFloodFindingsEndpoint(t *testing.T) {
	t.Setenv("NETRA_PROTECTED_DESTINATIONS", "198.51.100.77")
	s, h := metricsTestServer(t)
	tr := flooddetect.NewTracker()
	s.WithFloodTracker(tr)
	now := time.Now().Unix()
	from := now - 1500
	quietThenFlood := func(ctx, dim string) metricstream.WireSeries {
		return ws(ctx, dim, "events/s", from, now, func(ts int64) float64 {
			if ts > now-60 {
				return 400
			}
			return 0
		})
	}
	steady := ws("ipv4.udppackets", "received", "packets/s", from, now, func(int64) float64 { return 900 })
	if _, err := s.metricsHub.Ingest(&metricstream.Batch{Node: "n1", To: now, Series: []metricstream.WireSeries{
		quietThenFlood("ip.tcp_syn_queue", "drops"), quietThenFlood("ip.tcp_syn_queue", "cookies"), steady,
	}}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-20 * time.Second)
	obs := func(at time.Time, a, b, c uint64) {
		tr.Observe("n1", at, []models.ShieldSourceStat{
			{Class: "syn", Address: "203.0.113.9", Attempts: a},
			{Class: "syn", Address: "198.51.100.77", Attempts: b},
			{Class: "syn", Address: "10.0.0.8", Attempts: c},
		})
	}
	obs(t0, 0, 0, 0)
	obs(time.Now(), 60000, 60000, 60000)

	code, body := authedGet(t, h, "/api/v1/security/floods?window=30m")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	nf := body["nodeFindings"].([]any)
	if len(nf) == 0 {
		t.Fatalf("no node finding: %v", body)
	}
	foundSYN := false
	for _, x := range nf {
		m := x.(map[string]any)
		if m["vector"] == "syn" && m["node"] == "n1" {
			foundSYN = true
		}
		if m["vector"] == "udp" {
			t.Fatalf("a steady UDP rate must not be flagged: %v", m)
		}
	}
	if !foundSYN {
		t.Fatalf("syn flood not found: %v", nf)
	}
	if body["sourcesWarming"] != false {
		t.Fatalf("warming %v", body["sourcesWarming"])
	}
	byAddr := map[string]map[string]any{}
	for _, x := range body["sourceFindings"].([]any) {
		m := x.(map[string]any)
		byAddr[m["address"].(string)] = m
	}
	pub := byAddr["203.0.113.9"]
	if pub == nil || pub["suggestion"] == nil || pub["lockout"] == nil {
		t.Fatalf("public source needs a suggestion and a lockout check: %v", pub)
	}
	if sg := pub["suggestion"].(map[string]any); sg["direction"] != "ingress" || sg["kind"] != "ip" {
		t.Fatalf("suggestion %v", sg)
	}
	prot := byAddr["198.51.100.77"]
	if prot == nil || prot["suggestion"] != nil || prot["noSuggestion"] == nil {
		t.Fatalf("a protected address must have its suggestion withheld: %v", prot)
	}
	priv := byAddr["10.0.0.8"]
	if priv == nil || priv["suggestion"] != nil {
		t.Fatalf("a private address must not be suggested: %v", priv)
	}
	if code, _ := authedGet(t, h, "/api/v1/security/floods?window=1m"); code != http.StatusBadRequest {
		t.Fatalf("short window accepted: %d", code)
	}
}

func TestFloodFindingsWithoutMetricsOrTracker(t *testing.T) {
	s, h := metricsTestServer(t)
	s.metricsHub = nil
	code, body := authedGet(t, h, "/api/v1/security/floods")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	gaps := strings.Join(toStrings(body["gaps"]), "|")
	if !strings.Contains(gaps, "metrics are disabled") || !strings.Contains(gaps, "per-source flood tracking is not running") {
		t.Fatalf("gaps %v", body["gaps"])
	}
	if body["nodeFindings"] == nil || body["sourceFindings"] == nil {
		t.Fatal("collections must serialise as [] not null")
	}
}

func TestTLSPostureEndpoint(t *testing.T) {
	s, h := metricsTestServer(t)
	s.store.Report(models.AgentReport{Node: "n1", ObservedAt: time.Now(), TLSFingerprints: []models.TLSFingerprintStat{
		{JA3: "a", JA4: "t10d0505h1_x_y", SNI: "old.example.com", Count: 3, Namespace: "shop", WorkloadName: "cart"},
		{JA3: "b", JA4: "t13d1516h2_x_y", SNI: "ok.example.com", Count: 30, Namespace: "shop", WorkloadName: "cart"},
	}})
	code, body := authedGet(t, h, "/api/v1/insights/tls-posture")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	sum := body["summary"].(map[string]any)
	if sum["hellos"].(float64) != 33 || sum["legacyMaxHellos"].(float64) != 3 {
		t.Fatalf("%v", sum)
	}
	fs := body["findings"].([]any)
	if len(fs) != 1 || fs[0].(map[string]any)["kind"] != "legacy-max-version" {
		t.Fatalf("%v", fs)
	}
}

func TestExportFlowSummaryEndpoint(t *testing.T) {
	s, h := metricsTestServer(t)
	rep := func(b, p uint64) {
		s.store.Report(models.AgentReport{Node: "n1", ObservedAt: time.Now(), Stats: []models.DestinationStat{
			{DestinationIP: "203.0.113.9", Port: 443, Protocol: "TCP", Direction: "egress", Bytes: b, Packets: p, Namespace: "=shop", WorkloadName: "cart"},
		}})
	}
	rep(100, 1)
	rep(1100, 11)
	get := func(q string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/export/flow-summary"+q, nil)
		req.Header.Set("Authorization", "Bearer api-secret")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	rr := get("?since=1h")
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var sum struct {
		Flows []map[string]any `json:"flows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sum); err != nil || len(sum.Flows) != 1 {
		t.Fatalf("%v %s", err, rr.Body)
	}
	f := sum.Flows[0]
	if f["octetDeltaCount"].(float64) != 1000 || f["destinationIPv4Address"] != "203.0.113.9" || f["protocolIdentifier"].(float64) != 6 {
		t.Fatalf("%v", f)
	}
	rr = get("?format=csv&since=1h")
	rows, err := csv.NewReader(rr.Body).ReadAll()
	if err != nil || len(rows) != 2 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv %v %v", err, rows)
	}
	if rows[1][12] != "'=shop" {
		t.Fatalf("formula character not neutralised: %q", rows[1][12])
	}
	rr = get("?format=jsonl&since=1h")
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/x-ndjson") || strings.Count(strings.TrimSpace(rr.Body.String()), "\n") != 0 {
		t.Fatalf("jsonl %d %q", rr.Code, rr.Body)
	}
	for _, bad := range []string{"?format=xml", "?since=nonsense"} {
		if rr := get(bad); rr.Code != 400 {
			t.Fatalf("%s: %d", bad, rr.Code)
		}
	}
	if rr := get("?limit=0&since=1h"); rr.Code != 200 {
		t.Fatalf("limit=0 falls back to the default: %d", rr.Code)
	}
}
