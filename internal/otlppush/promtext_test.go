// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package otlppush

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// decoded mirrors the OTLP/JSON we emit, with the real JSON types (counts
// are strings, values are numbers) so tests assert the wire format rather
// than Go-side map shapes.
type decoded struct {
	ResourceMetrics []struct {
		Resource struct {
			Attributes []attr `json:"attributes"`
		} `json:"resource"`
		ScopeMetrics []struct {
			Metrics []metric `json:"metrics"`
		} `json:"scopeMetrics"`
	} `json:"resourceMetrics"`
}

type attr struct {
	Key   string `json:"key"`
	Value struct {
		StringValue string `json:"stringValue"`
	} `json:"value"`
}

type metric struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Gauge       *struct {
		DataPoints []numPoint `json:"dataPoints"`
	} `json:"gauge"`
	Sum *struct {
		AggregationTemporality int        `json:"aggregationTemporality"`
		IsMonotonic            bool       `json:"isMonotonic"`
		DataPoints             []numPoint `json:"dataPoints"`
	} `json:"sum"`
	Histogram *struct {
		AggregationTemporality int          `json:"aggregationTemporality"`
		DataPoints             []histPoint2 `json:"dataPoints"`
	} `json:"histogram"`
}

type numPoint struct {
	Attributes        []attr  `json:"attributes"`
	StartTimeUnixNano string  `json:"startTimeUnixNano"`
	TimeUnixNano      string  `json:"timeUnixNano"`
	AsDouble          float64 `json:"asDouble"`
}

type histPoint2 struct {
	Count          string    `json:"count"`
	Sum            *float64  `json:"sum"`
	BucketCounts   []string  `json:"bucketCounts"`
	ExplicitBounds []float64 `json:"explicitBounds"`
	Attributes     []attr    `json:"attributes"`
}

func convert(t *testing.T, text string) []metric {
	t.Helper()
	start := time.Unix(1000, 0)
	now := time.Unix(2000, 0)
	doc, n, err := PromToOTLP([]byte(text), start, now, map[string]string{"service.name": "netra"})
	if err != nil {
		t.Fatalf("PromToOTLP: %v", err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var d decoded
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(d.ResourceMetrics) != 1 || len(d.ResourceMetrics[0].ScopeMetrics) != 1 {
		t.Fatalf("unexpected envelope: %s", raw)
	}
	ms := d.ResourceMetrics[0].ScopeMetrics[0].Metrics
	if n != len(ms) {
		t.Fatalf("reported %d metrics, body has %d", n, len(ms))
	}
	return ms
}

func find(ms []metric, name, kind string) *metric {
	for i := range ms {
		m := &ms[i]
		if m.Name != name {
			continue
		}
		switch kind {
		case "gauge":
			if m.Gauge != nil {
				return m
			}
		case "sum":
			if m.Sum != nil {
				return m
			}
		case "histogram":
			if m.Histogram != nil {
				return m
			}
		}
	}
	return nil
}

func TestPromToOTLPCounterGaugeAndLabels(t *testing.T) {
	ms := convert(t, `# HELP netra_http_requests_total HTTP requests observed by netrad.
# TYPE netra_http_requests_total counter
netra_http_requests_total 42
# HELP netra_agents_total Node agents known to the controller.
# TYPE netra_agents_total gauge
netra_agents_total 3
# HELP netra_ebpf_program_attached Whether a program is attached.
# TYPE netra_ebpf_program_attached gauge
netra_ebpf_program_attached{program="netra_cgroup_egress"} 1.0000
netra_ebpf_program_attached{program="say \"hi\"\\there"} 0.5000
`)

	c := find(ms, "netra_http_requests_total", "sum")
	if c == nil {
		t.Fatalf("counter not exported as sum: %+v", ms)
	}
	if !c.Sum.IsMonotonic || c.Sum.AggregationTemporality != 2 {
		t.Fatalf("counter must be a monotonic cumulative sum: %+v", c.Sum)
	}
	if c.Description != "HTTP requests observed by netrad." {
		t.Fatalf("help lost: %q", c.Description)
	}
	p := c.Sum.DataPoints[0]
	if p.AsDouble != 42 || p.StartTimeUnixNano != "1000000000000" || p.TimeUnixNano != "2000000000000" {
		t.Fatalf("counter point wrong: %+v", p)
	}

	g := find(ms, "netra_agents_total", "gauge")
	if g == nil || g.Gauge.DataPoints[0].AsDouble != 3 {
		t.Fatalf("gauge wrong: %+v", g)
	}
	if g.Gauge.DataPoints[0].StartTimeUnixNano != "" {
		t.Fatal("gauge must not carry a start time")
	}

	lg := find(ms, "netra_ebpf_program_attached", "gauge")
	if lg == nil || len(lg.Gauge.DataPoints) != 2 {
		t.Fatalf("labeled gauge should keep both series: %+v", lg)
	}
	if got := lg.Gauge.DataPoints[1].Attributes[0].Value.StringValue; got != `say "hi"\there` {
		t.Fatalf("label escapes not decoded: %q", got)
	}
}

func TestPromToOTLPHistogram(t *testing.T) {
	ms := convert(t, `# HELP netra_tcp_srtt_us Per-flow smoothed RTT.
# TYPE netra_tcp_srtt_us histogram
netra_tcp_srtt_us_bucket{le="100"} 2
netra_tcp_srtt_us_bucket{le="500"} 5
netra_tcp_srtt_us_bucket{le="+Inf"} 9
netra_tcp_srtt_us_sum 3100
netra_tcp_srtt_us_count 9
`)
	h := find(ms, "netra_tcp_srtt_us", "histogram")
	if h == nil {
		t.Fatalf("histogram missing: %+v", ms)
	}
	if len(ms) != 1 {
		t.Fatalf("_bucket/_sum/_count must fold into one metric, got %d", len(ms))
	}
	dp := h.Histogram.DataPoints[0]
	if !reflect.DeepEqual(dp.ExplicitBounds, []float64{100, 500}) {
		t.Fatalf("bounds = %v", dp.ExplicitBounds)
	}
	// Cumulative 2,5,9 must become per-bucket 2,3,4.
	if !reflect.DeepEqual(dp.BucketCounts, []string{"2", "3", "4"}) {
		t.Fatalf("bucketCounts = %v", dp.BucketCounts)
	}
	if dp.Count != "9" || dp.Sum == nil || *dp.Sum != 3100 {
		t.Fatalf("count/sum = %s / %v", dp.Count, dp.Sum)
	}
}

// The overflow bucket comes from _count, so the per-bucket counts always add
// up to the reported count even when the +Inf sample disagrees with it.
func TestPromToOTLPHistogramOverflowFollowsCount(t *testing.T) {
	ms := convert(t, `# TYPE h histogram
h_bucket{le="1"} 3
h_bucket{le="+Inf"} 7
h_sum 10
h_count 9
`)
	dp := find(ms, "h", "histogram").Histogram.DataPoints[0]
	if !reflect.DeepEqual(dp.BucketCounts, []string{"3", "6"}) || dp.Count != "9" {
		t.Fatalf("counts=%v count=%s, want [3 6] / 9", dp.BucketCounts, dp.Count)
	}

	// Corrupt data (count below the last finite bucket) must not underflow.
	ms = convert(t, `# TYPE h histogram
h_bucket{le="1"} 5
h_bucket{le="+Inf"} 5
h_sum 1
h_count 2
`)
	dp = find(ms, "h", "histogram").Histogram.DataPoints[0]
	if !reflect.DeepEqual(dp.BucketCounts, []string{"5", "0"}) {
		t.Fatalf("underflow not clamped: %v", dp.BucketCounts)
	}
}

// /metrics really does emit netra_tcp_retransmissions as both a gauge and a
// histogram. They must stay two metrics, not merge into one or clobber.
func TestPromToOTLPSameNameGaugeAndHistogram(t *testing.T) {
	ms := convert(t, `# HELP netra_tcp_retransmissions TCP retransmission callbacks.
# TYPE netra_tcp_retransmissions gauge
netra_tcp_retransmissions 7
# HELP netra_tcp_retransmissions Per-flow retransmission counts.
# TYPE netra_tcp_retransmissions histogram
netra_tcp_retransmissions_bucket{le="1"} 1
netra_tcp_retransmissions_bucket{le="+Inf"} 2
netra_tcp_retransmissions_sum 3
netra_tcp_retransmissions_count 2
`)
	g := find(ms, "netra_tcp_retransmissions", "gauge")
	h := find(ms, "netra_tcp_retransmissions", "histogram")
	if g == nil || h == nil {
		t.Fatalf("both kinds must survive: gauge=%v hist=%v", g != nil, h != nil)
	}
	if g.Gauge.DataPoints[0].AsDouble != 7 {
		t.Fatalf("gauge value clobbered: %+v", g.Gauge.DataPoints[0])
	}
	if h.Histogram.DataPoints[0].Count != "2" {
		t.Fatalf("histogram wrong: %+v", h.Histogram.DataPoints[0])
	}
}

func TestPromToOTLPSkipsUnrepresentableAndMalformed(t *testing.T) {
	ms := convert(t, `# TYPE ok gauge
ok 1
# TYPE nan gauge
nan NaN
# TYPE inf gauge
inf +Inf
this is not a sample
broken{label="unterminated 5
# TYPE after gauge
after 2
`)
	if find(ms, "ok", "gauge") == nil || find(ms, "after", "gauge") == nil {
		t.Fatalf("good samples around bad lines were lost: %+v", ms)
	}
	for _, name := range []string{"nan", "inf", "broken"} {
		if find(ms, name, "gauge") != nil {
			t.Fatalf("%s should have been skipped", name)
		}
	}
}

func TestPromToOTLPUntypedIsGauge(t *testing.T) {
	ms := convert(t, "mystery 5\n")
	if find(ms, "mystery", "gauge") == nil {
		t.Fatalf("untyped sample should export as gauge: %+v", ms)
	}
}

func TestPromToOTLPResourceAttributes(t *testing.T) {
	doc, _, err := PromToOTLP([]byte("x 1\n"), time.Unix(1, 0), time.Unix(2, 0),
		map[string]string{"service.name": "netra", "service.instance.id": "pod-a"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(doc)
	var d decoded
	_ = json.Unmarshal(raw, &d)
	got := map[string]string{}
	for _, a := range d.ResourceMetrics[0].Resource.Attributes {
		got[a.Key] = a.Value.StringValue
	}
	if got["service.name"] != "netra" || got["service.instance.id"] != "pod-a" {
		t.Fatalf("resource attrs = %v", got)
	}
}
