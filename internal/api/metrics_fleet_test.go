// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/fleet"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/tsdb"
)

func TestMetricsSummaryAndFleetRollup(t *testing.T) {
	s, h := metricsTestServer(t)
	now := time.Now().Unix()
	ws := metricstream.WireSeries{Series: tsdb.Series{Context: "system.cpu", Chart: "system.cpu", Dimension: "user"}}
	for ts := now - 60; ts <= now; ts++ {
		ws.Points = append(ws.Points, [3]float64{float64(ts), 1, 1})
	}
	if _, err := s.metricsHub.Ingest(&metricstream.Batch{Node: "n1", To: now, Series: []metricstream.WireSeries{ws}}); err != nil {
		t.Fatal(err)
	}
	code, body := authedGet(t, h, "/api/v1/metrics/summary")
	if code != http.StatusOK || body["available"] != true || body["nodes"].(float64) != 1 || body["anomalyRate"].(float64) != 100 {
		t.Fatalf("summary %d %v", code, body)
	}

	var peerAuth string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/metrics/summary" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(fleet.MetricsSummary{Available: true, Nodes: 3, Series: 900, AlertsCritical: 2})
	}))
	defer peer.Close()
	t.Setenv("NETRA_CLUSTER_NAME", "east")
	t.Setenv("NETRA_FLEET_PEERS", "west|"+peer.URL+"|peer-key|acme,dead|http://127.0.0.1:1|")
	code, body = authedGet(t, h, "/api/v1/metrics/fleet")
	if code != http.StatusOK {
		t.Fatalf("fleet %d %v", code, body)
	}
	cs := body["clusters"].([]any)
	if len(cs) != 3 || cs[0].(map[string]any)["name"] != "east" || cs[1].(map[string]any)["ok"] != true || cs[2].(map[string]any)["ok"] != false {
		t.Fatalf("clusters %v", cs)
	}
	tot := body["totals"].(map[string]any)
	if tot["nodes"].(float64) != 4 || tot["okClusters"].(float64) != 2 || tot["alertsCritical"].(float64) != 2 || tot["anomalyRate"].(float64) != 25 {
		t.Fatalf("totals %v", tot)
	}
	if peerAuth != "Bearer peer-key" {
		t.Fatalf("peer auth %q", peerAuth)
	}
}
