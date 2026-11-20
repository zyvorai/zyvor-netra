// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCapabilityAddPostsName(t *testing.T) {
	var gotPath string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	withArgs(t, "ebpf", "capability", "add", "CAP_NET_RAW")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/capability" || body["name"] != "CAP_NET_RAW" {
		t.Fatalf("unexpected request: path=%s body=%#v", gotPath, body)
	}
}

func TestCapabilityDeletePostsToDeletePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	withArgs(t, "ebpf", "capability", "del", "CAP_NET_ADMIN")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/capability/delete" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
}
