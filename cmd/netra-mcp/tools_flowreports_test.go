// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBeaconAndCoverageToolsAreReadOnly(t *testing.T) {
	var method, path, query string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, query = r.Method, r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	c := testClient(t, ts)
	ro, err := buildServer(c, false)
	if err != nil {
		t.Fatal(err)
	}
	names := toolNames(t, ro)
	for _, n := range []string{"netra_security_beacons", "netra_insights_netpol_coverage"} {
		if !contains(names, n) {
			t.Fatalf("%s must be available without NETRA_MCP_ALLOW_MUTATIONS", n)
		}
	}
	for _, tc := range []struct {
		tool  string
		args  map[string]any
		path  string
		query string
	}{
		{"netra_security_beacons", map[string]any{"window": "6h", "include_private": "true", "min_events": 12}, "/api/v1/security/beacons", "include_private=true&min_events=12&window=6h"},
		{"netra_insights_netpol_coverage", map[string]any{"namespace": "shop", "all": "true"}, "/api/v1/insights/netpol-coverage", "all=true&namespace=shop"},
		{"netra_insights_volume_shift", map[string]any{"baseline_mode": "same-time"}, "/api/v1/insights/volume-shift", "baseline_mode=same-time"},
	} {
		if res := callTool(t, c, false, tc.tool, tc.args); res.IsError {
			t.Fatalf("%s: %+v", tc.tool, res)
		}
		if method != "GET" || path != tc.path || query != tc.query {
			t.Fatalf("%s: %s %s?%s", tc.tool, method, path, query)
		}
	}
}
