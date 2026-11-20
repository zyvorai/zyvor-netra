// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/tsdb"
)

func TestMetricsAnomaliesRanksAndCorrelates(t *testing.T) {
	s, h := metricsTestServer(t)
	now := time.Now().Unix()
	quiet := metricstream.WireSeries{Series: tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: "user"}}
	loud := metricstream.WireSeries{Series: tsdb.Series{Context: "disk.io", Chart: "disk.io_sda", Dimension: "writes"}}
	for ts := now - 599; ts <= now; ts++ {
		quiet.Points = append(quiet.Points, [3]float64{float64(ts), float64(10 + ts%2), 0})
		v, a := 100.0, 0.0
		if ts > now-60 {
			v, a = 5000, 1
		}
		loud.Points = append(loud.Points, [3]float64{float64(ts), v, a})
	}
	if _, err := s.metricsHub.Ingest(&metricstream.Batch{Node: "n1", To: now, Series: []metricstream.WireSeries{quiet, loud}}); err != nil {
		t.Fatal(err)
	}
	code, body := authedGet(t, h, "/api/v1/metrics/anomalies?after=-600")
	if code != http.StatusOK {
		t.Fatalf("anomalies %d %v", code, body)
	}
	ranked := body["ranked"].([]any)
	if len(ranked) != 1 || ranked[0].(map[string]any)["dimension"] != "writes" {
		t.Fatalf("ranked %v", ranked)
	}
	nodes := body["nodes"].([]any)
	if len(nodes) != 1 || nodes[0].(map[string]any)["anomalyRate"].(float64) <= 0 {
		t.Fatalf("nodes %v", nodes)
	}
	path := fmt.Sprintf("/api/v1/metrics/anomalies?after=-600&highlight_after=%d&highlight_before=%d", now-59, now)
	code, body = authedGet(t, h, path)
	if code != http.StatusOK {
		t.Fatalf("highlight %d %v", code, body)
	}
	cor := body["correlated"].([]any)
	if len(cor) == 0 || cor[0].(map[string]any)["dimension"] != "writes" {
		t.Fatalf("correlated %v", cor)
	}
	for _, q := range []string{"?after=-10&before=-20", "?after=-600&highlight_after=-5&highlight_before=-10"} {
		if code, _ := authedGet(t, h, "/api/v1/metrics/anomalies"+q); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q, code)
		}
	}
}
