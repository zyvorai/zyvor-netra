// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFlowReportCommandsBuildQueries(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Method + " " + r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"security", "beacons"}, "GET /api/v1/security/beacons"},
		{[]string{"security", "beacons", "--window", "6h", "--namespace", "a b", "--node", "n1", "--min-events", "12", "--min-period", "1m", "--min-score", "0.9", "--include-private", "--limit", "5"},
			"GET /api/v1/security/beacons?include_private=true&limit=5&min_events=12&min_period=1m&min_score=0.9&namespace=a+b&node=n1&window=6h"},
		{[]string{"insights", "netpol-coverage"}, "GET /api/v1/insights/netpol-coverage"},
		{[]string{"insights", "netpol-coverage", "--namespace", "shop", "--all", "--window", "1h", "--limit", "10"},
			"GET /api/v1/insights/netpol-coverage?all=true&limit=10&namespace=shop&window=1h"},
		{[]string{"insights", "volume-shift", "--baseline-mode", "same-time", "--factor", "2"}, "GET /api/v1/insights/volume-shift?baseline_mode=same-time&factor=2"},
		{[]string{"insights", "dependency-drift", "--public-only"}, "GET /api/v1/insights/dependency-drift?public_only=true"},
	} {
		got = ""
		if err := run(tc.args); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if got != tc.want {
			t.Fatalf("%v: got %q want %q", tc.args, got, tc.want)
		}
	}
	for _, bad := range [][]string{
		{"security", "beacons", "--window"},
		{"security", "beacons", "--apply"},
		{"insights", "netpol-coverage", "--public-only"},
		{"insights", "volume-shift", "--public-only"},
		{"insights", "dependency-drift", "--baseline-mode", "same-time"},
	} {
		got = ""
		err := run(bad)
		if err == nil || got != "" || !strings.Contains(err.Error(), "--") {
			t.Fatalf("%v: err=%v request=%q", bad, err, got)
		}
	}
}
