// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/metricalert"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/tsdb"
)

func TestAIDigestCitesMetricAlertsAndAnomalies(t *testing.T) {
	s, _ := metricsTestServer(t)
	now := time.Now().Unix()
	ram := metricstream.WireSeries{Series: tsdb.Series{Context: "mem.used_percent", Chart: "mem.used_percent", Dimension: "used", Units: "%"}}
	loud := metricstream.WireSeries{Series: tsdb.Series{Context: "net.net", Chart: "net.eth0", Dimension: "received"}}
	for ts := now - 899; ts <= now; ts++ {
		ram.Points = append(ram.Points, [3]float64{float64(ts), 99, 0})
		a := 0.0
		if ts > now-300 {
			a = 1
		}
		loud.Points = append(loud.Points, [3]float64{float64(ts), 1, a})
	}
	if _, err := s.metricsHub.Ingest(&metricstream.Batch{Node: "n1", To: now, Series: []metricstream.WireSeries{ram, loud}}); err != nil {
		t.Fatal(err)
	}
	eng, err := metricalert.New(metricalert.Options{
		Rules:   []metricalert.Rule{{Name: "ram_in_use", Context: "mem.used_percent", Lookup: "average -1m", Every: "1s", Crit: "$this > 95", Units: "%", Info: "RAM in use"}},
		Sources: s.metricsHub.Sources,
	})
	if err != nil {
		t.Fatal(err)
	}
	eng.Evaluate(time.Unix(now, 0))
	h := s.WithMetricAlerts(eng).Handler()

	code, body := authedGet(t, h, "/api/v1/ai/digest")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	card := body["card"].(string)
	if body["severity"] != "critical" || !strings.Contains(card, "ram_in_use critical on n1 mem.used_percent") {
		t.Fatalf("digest card:\n%s", card)
	}
	metrics := body["brief"].(map[string]any)["snapshot"].(map[string]any)["metrics"].([]any)
	kinds := map[string]bool{}
	for _, m := range metrics {
		kinds[m.(map[string]any)["kind"].(string)] = true
	}
	if !kinds["metric-alert"] || !kinds["metric-anomaly"] {
		t.Fatalf("metrics findings %v", metrics)
	}
	// Reading the digest never changes alert state.
	if a := eng.Active(); len(a) != 1 || a[0].Acked || a[0].Silenced {
		t.Fatalf("alert state changed: %+v", a)
	}
}
