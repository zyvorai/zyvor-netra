// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnRateLimitAddPostsSelectorAndPerSecond(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/ebpf/conn-rate-limit" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	withArgs(t, "ebpf", "conn-rate-limit", "add", "--namespace", "payments", "--label", "tier=hot", "--per-second", "50")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	selector, _ := body["selector"].(map[string]any)
	if selector == nil || selector["namespace"] != "payments" {
		t.Fatalf("unexpected selector: %#v", body)
	}
	labels, _ := selector["labels"].(map[string]any)
	if labels == nil || labels["tier"] != "hot" {
		t.Fatalf("unexpected labels: %#v", selector)
	}
	if body["perSecond"] != float64(50) {
		t.Fatalf("unexpected perSecond: %#v", body)
	}
}

func TestConnRateLimitAddRejectsZeroPerSecond(t *testing.T) {
	withArgs(t, "ebpf", "conn-rate-limit", "add", "--namespace", "payments", "--per-second", "0")
	if err := ebpf(); err == nil {
		t.Fatal("expected an error for --per-second 0")
	}
}

func TestConnRateLimitDeleteHitsIDPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != "DELETE" {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	withArgs(t, "ebpf", "conn-rate-limit", "del", "connratelimit-3")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/conn-rate-limit/connratelimit-3" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
}
