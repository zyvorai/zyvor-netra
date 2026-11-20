// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSynDropAddPostsAddressAndDirection(t *testing.T) {
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
	withArgs(t, "ebpf", "syn-drop", "add", "203.0.113.9", "egress")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/syn-drop" || body["address"] != "203.0.113.9" || body["direction"] != "egress" {
		t.Fatalf("unexpected request: path=%s body=%#v", gotPath, body)
	}
}

func TestSynDropDeletePostsToDeletePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	withArgs(t, "ebpf", "syn-drop", "del", "203.0.113.9", "ingress")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/syn-drop/delete" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
}

func TestSynDropCIDRAddPostsCIDRAndDirection(t *testing.T) {
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
	withArgs(t, "ebpf", "syn-drop-cidr", "add", "203.0.113.0/24", "egress")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/syn-drop-cidr" || body["cidr"] != "203.0.113.0/24" || body["direction"] != "egress" {
		t.Fatalf("unexpected request: path=%s body=%#v", gotPath, body)
	}
}

func TestSynDropCIDRDeletePostsToDeletePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	withArgs(t, "ebpf", "syn-drop-cidr", "del", "203.0.113.0/24", "ingress")

	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/ebpf/syn-drop-cidr/delete" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
}
