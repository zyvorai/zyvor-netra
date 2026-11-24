// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFlowDriftAndIncidentToolsAreReadOnly(t *testing.T) {
	type seen struct{ method, path, query, body string }
	var got seen
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = seen{r.Method, r.URL.Path, r.URL.RawQuery, string(b)}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	c := testClient(t, ts)
	ro, err := buildServer(c, false)
	if err != nil {
		t.Fatal(err)
	}
	names := toolNames(t, ro)
	for _, n := range []string{"netra_insights_dependency_drift", "netra_insights_volume_shift", "netra_incident_verify", "netra_incident_report"} {
		if !contains(names, n) {
			t.Fatalf("%s must be available without NETRA_MCP_ALLOW_MUTATIONS", n)
		}
	}
	if res := callTool(t, c, false, "netra_insights_dependency_drift", map[string]any{"recent": "30m", "public_only": "true"}); res.IsError {
		t.Fatalf("%+v", res)
	}
	if got.method != "GET" || got.path != "/api/v1/insights/dependency-drift" || got.query != "public_only=true&recent=30m" {
		t.Fatalf("%+v", got)
	}
	if res := callTool(t, c, false, "netra_insights_volume_shift", map[string]any{"factor": "2"}); res.IsError || got.query != "factor=2" {
		t.Fatalf("%+v %+v", res, got)
	}
	if res := callTool(t, c, false, "netra_incident_verify", map[string]any{"bundle": "{}", "seal": "{}"}); res.IsError {
		t.Fatalf("%+v", res)
	}
	var body map[string]string
	if got.method != "POST" || got.path != "/api/v1/incident/verify" || json.Unmarshal([]byte(got.body), &body) != nil || body["bundle"] != "{}" || body["seal"] != "{}" {
		t.Fatalf("%+v", got)
	}
	if res := callTool(t, c, false, "netra_incident_report", map[string]any{"bundle": "{}", "format": "markdown"}); res.IsError {
		t.Fatalf("%+v", res)
	}
	if got.path != "/api/v1/incident/report" || got.query != "format=markdown" {
		t.Fatalf("format must go in the query, not the body: %+v", got)
	}
}
