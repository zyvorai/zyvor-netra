// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/otlppush"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/workloadobs"
)

var wt0 = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func wlAgent(node string, wl map[string][2]uint64) models.AgentStatus {
	r := models.AgentReport{Node: node}
	cg := uint64(100)
	for name, v := range wl {
		cg++
		r.Stats = append(r.Stats, models.DestinationStat{
			CgroupID: cg, Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: name,
			Hook: "egress", Direction: "egress", Protocol: "tcp", DestinationIP: "10.0.0.2", Port: 80,
			Packets: v[0], Bytes: v[1],
		})
		r.HTTPStatus = append(r.HTTPStatus,
			models.HTTPStatusStat{CgroupID: cg, Status: 200, Count: v[0], Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: name},
			models.HTTPStatusStat{CgroupID: cg, Status: 503, Count: v[1] / 100, Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: name})
	}
	return models.AgentStatus{AgentReport: r}
}

func devServer(t *testing.T, o *workloadobs.Observer) http.Handler {
	t.Helper()
	t.Setenv("NETRA_API_KEY", "")
	t.Setenv("NETRA_AGENT_KEY", "")
	t.Setenv("NETRA_METRICS_TOKEN", "")
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, store.New()).WithWorkloadObs(o).Handler()
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("/metrics = %d", rec.Code)
	}
	return rec.Body.String()
}

func mustObserver(t *testing.T, cfg workloadobs.Config) *workloadobs.Observer {
	t.Helper()
	o, err := workloadobs.NewObserver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestWorkloadSeriesAreExportedAsCountersWithAnOtherBucket(t *testing.T) {
	o := mustObserver(t, workloadobs.Config{PromSeries: true, MaxWorkloads: 1})
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {0, 0}, "batch": {0, 0}})}, wt0, nil)
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {500, 5000}, "batch": {10, 100}})}, wt0.Add(time.Minute), nil)
	out := scrape(t, devServer(t, o))

	for _, want := range []string{
		"# TYPE netra_workload_packets_total counter",
		`netra_workload_packets_total{namespace="shop",workload="Deployment/web"} 500`,
		`netra_workload_bytes_total{namespace="shop",workload="Deployment/web"} 5000`,
		`netra_workload_packets_total{namespace="__other__",workload="__other__"} 10`,
		"netra_workload_series_named 1",
		"netra_workload_series_max 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, grepLines(out, "netra_workload_packets", "series"))
		}
	}
	if strings.Contains(out, `workload="Deployment/batch"`) {
		t.Error("a workload beyond the cap must not get its own series")
	}
}

func TestWorkloadSeriesOffByDefaultAndSLOOnlyModeExportsOnlySLOGauges(t *testing.T) {
	// (netra_workload_cgroups_resolved is an older aggregate gauge, not ours.)
	if out := scrape(t, devServer(t, nil)); strings.Contains(out, "netra_workload_packets_total") ||
		strings.Contains(out, "netra_workload_series_") || strings.Contains(out, "netra_slo_") {
		t.Fatal("with no observer, /metrics must carry no per-workload or SLO series")
	}

	defs, _ := workloadobs.ParseDefinitions(`[{"name":"web-up","sli":"http_5xx","targetPct":99.9,"window":"7d"}]`)
	o := mustObserver(t, workloadobs.Config{SLOs: defs}) // PromSeries false
	// SLOStatus windows off time.Now(), not a fixed test clock, so these ticks
	// must stay within the 7d window regardless of when the test runs.
	sloNow := time.Now()
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {0, 0}})}, sloNow, nil)
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {1000, 0}})}, sloNow.Add(time.Minute), nil)
	out := scrape(t, devServer(t, o))
	if strings.Contains(out, "netra_workload_packets_total") {
		t.Fatal("workload series must stay off unless NETRA_METRICS_WORKLOAD_LABELS is on")
	}
	for _, want := range []string{
		`netra_slo_target_ratio{slo="web-up"} 0.999000`,
		`netra_slo_has_data{slo="web-up"} 1`,
		`netra_slo_alert_state{slo="web-up"} 0`,
		`netra_slo_budget_remaining{slo="web-up"} 1.000000`,
		`netra_slo_burn_rate{slo="web-up",window="1h"} 0.0000`,
		`netra_slo_burn_rate{slo="web-up",window="5m"} 0.0000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, grepLines(out, "netra_slo"))
		}
	}
}

func TestLabelValuesAreEscapedForTheTextFormat(t *testing.T) {
	o := mustObserver(t, workloadobs.Config{PromSeries: true})
	nasty := "we\"ird\\name\nline2"
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{nasty: {0, 0}})}, wt0, nil)
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{nasty: {7, 0}})}, wt0.Add(time.Minute), nil)
	out := scrape(t, devServer(t, o))
	if !strings.Contains(out, `workload="Deployment/we\"ird\\name\nline2"`) {
		t.Fatalf("label not escaped per the text format:\n%s", grepLines(out, "netra_workload_packets_total"))
	}
	// No series line may be broken across lines by a raw newline in a label.
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "line2") {
			t.Fatalf("a raw newline in a label split a series line: %q", l)
		}
	}
}

// Every family this feature adds must be declared once, with a matching TYPE,
// and every series must sit under its own family: a strict parser rejects
// anything else.
func TestWorkloadAndSLOFamiliesAreWellFormed(t *testing.T) {
	defs, _ := workloadobs.ParseDefinitions(`[{"name":"a","sli":"http_5xx","targetPct":99.9},{"name":"b","sli":"dns_failure","targetPct":99}]`)
	o := mustObserver(t, workloadobs.Config{PromSeries: true, SLOs: defs})
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {0, 0}})}, wt0, nil)
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {50, 500}})}, wt0.Add(time.Minute), nil)
	out := scrape(t, devServer(t, o))

	typeRE := regexp.MustCompile(`^# TYPE (netra_(?:workload|slo)_\S+) (\S+)$`)
	types := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if m := typeRE.FindStringSubmatch(l); m != nil {
			if prev, dup := types[m[1]]; dup {
				t.Errorf("family %s declared twice (%s then %s)", m[1], prev, m[2])
			}
			types[m[1]] = m[2]
		}
	}
	if len(types) < 15 {
		t.Fatalf("only %d workload/slo families found", len(types))
	}
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "netra_workload_") && !strings.HasPrefix(l, "netra_slo_") {
			continue
		}
		name := l[:strings.IndexAny(l, "{ ")]
		if _, ok := types[name]; !ok {
			t.Errorf("series %q has no TYPE line for family %q", l, name)
		}
	}
	for name, typ := range types {
		if strings.HasPrefix(name, "netra_workload_") && strings.HasSuffix(name, "_total") && typ != "counter" {
			t.Errorf("%s is %s, want counter", name, typ)
		}
	}
}

func TestCardinalityIsBoundedRegardlessOfWorkloadCount(t *testing.T) {
	o := mustObserver(t, workloadobs.Config{PromSeries: true, MaxWorkloads: 3})
	base, grown := map[string][2]uint64{}, map[string][2]uint64{}
	for i := range 200 {
		n := fmt.Sprintf("w%03d", i)
		base[n], grown[n] = [2]uint64{0, 0}, [2]uint64{uint64(10 + i), 100}
	}
	o.Tick([]models.AgentStatus{wlAgent("n1", base)}, wt0, nil)
	o.Tick([]models.AgentStatus{wlAgent("n1", grown)}, wt0.Add(time.Minute), nil)
	out := scrape(t, devServer(t, o))
	n := strings.Count(out, "netra_workload_packets_total{")
	if n != 3+1 {
		t.Fatalf("packets series = %d for 200 active workloads, want 3 named + __other__", n)
	}
}

func TestSLOEndpointReportsStatusWithReadableDurations(t *testing.T) {
	defs, _ := workloadobs.ParseDefinitions(`[{"name":"checkout","namespace":"shop","workload":"Deployment/web","sli":"http_5xx","targetPct":99.9,"window":"7d"}]`)
	o := mustObserver(t, workloadobs.Config{SLOs: defs})
	// The /api/v1/slo handler evaluates the windows against the real clock, so the
	// timeline must end "now". Anchoring it to the fixed wt0 made this test pass only
	// for the few minutes after wt0+100min and fail on every run after that.
	now := time.Now().Add(-100 * time.Minute)
	var ok, bad uint64
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {0, 0}})}, now, nil)
	for range 20 {
		ok += 1000
		bad += 4000 // v[1]/100 = 40 5xx per 1000 responses
		now = now.Add(5 * time.Minute)
		o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {ok, bad}})}, now, nil)
	}
	h := devServer(t, o)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/slo", nil))
	if rec.Code != 200 {
		t.Fatalf("/api/v1/slo = %d", rec.Code)
	}
	var got struct {
		Enabled bool `json:"enabled"`
		Items   []struct {
			Name     string `json:"name"`
			SLI      string `json:"sli"`
			Window   string `json:"window"`
			Severity string `json:"severity"`
			HasData  bool   `json:"hasData"`
			Windows  []struct {
				Kind, Long, Short string
				Firing            bool
			} `json:"windows"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || len(got.Items) != 1 {
		t.Fatalf("response = %s", rec.Body.String())
	}
	it := got.Items[0]
	if it.Name != "checkout" || it.SLI != "http_5xx" || it.Window != "7d" || it.Severity != "page" || !it.HasData {
		t.Fatalf("item = %+v", it)
	}
	foundHourly := false
	for _, w := range it.Windows {
		if w.Kind == "page" && w.Long == "1h" && w.Short == "5m" && w.Firing {
			foundHourly = true
		}
	}
	if !foundHourly {
		t.Fatalf("expected a firing page 1h/5m window with human-readable durations: %+v", it.Windows)
	}
}

func TestSLOEndpointWhenDisabledSaysSo(t *testing.T) {
	rec := httptest.NewRecorder()
	devServer(t, nil).ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/slo", nil))
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got["enabled"] != false {
		t.Fatalf("disabled response = %d %s", rec.Code, rec.Body.String())
	}
	if items, _ := got["items"].([]any); items == nil || len(items) != 0 {
		t.Fatalf("items must be an empty array, got %v", got["items"])
	}
}

// The labelled counters must survive the trip through the OTLP exporter
// added in 0.27.98: real /metrics text in, OTLP sums with attributes out.
func TestWorkloadSeriesConvertToOTLPSumsWithAttributes(t *testing.T) {
	o := mustObserver(t, workloadobs.Config{PromSeries: true})
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {0, 0}})}, wt0, nil)
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {42, 0}})}, wt0.Add(time.Minute), nil)
	text := scrape(t, devServer(t, o))

	doc, n, err := otlppush.PromToOTLP([]byte(text), wt0, wt0.Add(time.Minute), map[string]string{"service.name": "netra"})
	if err != nil || n == 0 {
		t.Fatalf("convert: n=%d err=%v", n, err)
	}
	raw, _ := json.Marshal(doc)
	s := string(raw)
	for _, want := range []string{`"name":"netra_workload_packets_total"`, `"isMonotonic":true`, `"key":"workload"`, `"stringValue":"Deployment/web"`, `"key":"namespace"`} {
		if !strings.Contains(s, want) {
			t.Errorf("OTLP body missing %s", want)
		}
	}
}

func TestSLOAndWorkloadRoutesNeedOnlyViewer(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/slo", nil)
	req.Pattern = "GET /api/v1/slo"
	if got := requiredRole(req); got.String() != "viewer" {
		t.Fatalf("GET /api/v1/slo needs %s, want viewer", got)
	}
}

func grepLines(s string, subs ...string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		for _, sub := range subs {
			if strings.Contains(l, sub) {
				out = append(out, l)
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

// Agents send top-N snapshots; the gauge is how an operator learns that a
// source is capped and per-workload counts for it are lower bounds.
func TestTruncationGaugeIsExportedPerSource(t *testing.T) {
	o := mustObserver(t, workloadobs.Config{PromSeries: true})
	small := models.AgentStatus{AgentReport: models.AgentReport{Node: "n1"}}
	o.Tick([]models.AgentStatus{small}, wt0, nil)
	out := scrape(t, devServer(t, o))
	for _, src := range workloadobs.Sources {
		if want := `netra_workload_report_truncated{source="` + src + `"} 0`; !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}

	// A flows report at the cap flips exactly that source.
	full := models.AgentReport{Node: "n1"}
	for i := range models.ReportCapFlows {
		full.Stats = append(full.Stats, models.DestinationStat{
			CgroupID: uint64(i + 1), Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "w",
			Hook: "egress", Direction: "egress", Protocol: "tcp", DestinationIP: "10.0.0.2", Port: uint16(i%60000 + 1), Packets: 1, Bytes: 1,
		})
	}
	o.Tick([]models.AgentStatus{{AgentReport: full}}, wt0.Add(time.Minute), nil)
	out = scrape(t, devServer(t, o))
	if !strings.Contains(out, `netra_workload_report_truncated{source="flows"} 1`) ||
		!strings.Contains(out, `netra_workload_report_truncated{source="http"} 0`) {
		t.Fatalf("truncation gauge wrong:\n%s", grepLines(out, "report_truncated"))
	}
}

func TestNoTCPWorkloadSeriesAreExported(t *testing.T) {
	// The agent reports the WORST-retransmitting sockets, so ratios built from it
	// would be biased; those series must not exist.
	o := mustObserver(t, workloadobs.Config{PromSeries: true})
	o.Tick([]models.AgentStatus{wlAgent("n1", map[string][2]uint64{"web": {0, 0}})}, wt0, nil)
	if out := scrape(t, devServer(t, o)); strings.Contains(out, "netra_workload_tcp_") {
		t.Fatalf("a biased TCP series is exported:\n%s", grepLines(out, "netra_workload_tcp_"))
	}
}
