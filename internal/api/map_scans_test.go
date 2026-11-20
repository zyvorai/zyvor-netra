// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func scanAgent(node string, stale bool, s ...models.MapScanStat) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, MapScans: s}, Stale: stale}
}

func TestMapScanMetricsReportTheWorstNodePerMap(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMapScanMetrics(rec, []models.AgentStatus{
		scanAgent("a", false,
			models.MapScanStat{Map: "flow_stats", Entries: 1000, Millis: 4.5, Batched: true},
			models.MapScanStat{Map: "tcp_health", Entries: 50, Millis: 1, Batched: true}),
		scanAgent("b", false, models.MapScanStat{Map: "flow_stats", Entries: 90000, Millis: 31.25, Batched: false}),
		scanAgent("gone", true, models.MapScanStat{Map: "flow_stats", Entries: 1e6, Millis: 9999}), // stale: ignored
	})
	out := rec.Body.String()
	for _, want := range []string{
		`netra_agent_map_scan_millis_max{map="flow_stats"} 31.250`,
		`netra_agent_map_scan_entries_max{map="flow_stats"} 90000`,
		`netra_agent_map_scan_unbatched_nodes{map="flow_stats"} 1`,
		`netra_agent_map_scan_unbatched_nodes{map="tcp_health"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "9999") || strings.Contains(out, "node") && strings.Contains(out, `node="`) {
		t.Fatalf("a stale node leaked or a node became a label:\n%s", out)
	}
}

func TestMapScanMetricsAreAbsentWhenNoAgentReportsThem(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMapScanMetrics(rec, []models.AgentStatus{scanAgent("a", false)})
	if rec.Body.Len() != 0 {
		t.Fatalf("an older agent must produce no series, got:\n%s", rec.Body.String())
	}
}
