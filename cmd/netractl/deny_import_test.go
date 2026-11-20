// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDenyImportParsesFileAndPosts(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ebpf/deny/import" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"applied":3,"failed":0,"results":[]}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	content := "# comment\n\nip 203.0.113.5 egress\ncidr 10.0.0.0/8 ingress\ndns evil.example.com\n"
	path := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := denyImport(path); err != nil {
		t.Fatal(err)
	}
	entries, ok := body["entries"].([]any)
	if !ok || len(entries) != 3 {
		t.Fatalf("unexpected entries: %#v", body)
	}
	first := entries[0].(map[string]any)
	if first["type"] != "ip" || first["value"] != "203.0.113.5" || first["direction"] != "egress" {
		t.Fatalf("unexpected first entry: %#v", first)
	}
}

func TestDenyImportRejectsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := denyImport(path); err == nil {
		t.Fatal("expected an error for a file with no entries")
	}
}

func TestDenyImportRejectsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(path, []byte("ip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := denyImport(path); err == nil {
		t.Fatal("expected an error for a line missing a value")
	}
}
