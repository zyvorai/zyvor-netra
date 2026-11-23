// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncidentBundleVerifyDiffRoundTrip(t *testing.T) {
	t.Setenv("NETRA_CLI_HELP", "plain")
	srv := httptest.NewServer(http.HandlerFunc(mockNetraAPI))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	dir := t.TempDir()
	a, b, z := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "c.tar.gz")

	for _, args := range [][]string{
		{"incident", "bundle", "--minutes", "5", "--out", a},
		{"incident", "bundle", "--minutes", "5", "--mask-ips", "--mask-key", "k", "--out", b},
		{"incident", "bundle", "--minutes", "5", "--out", z},
	} {
		if err := run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if st, err := os.Stat(z); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("archive: %v %v", st, err)
	}
	for _, f := range []string{a, b, z} {
		if err := run([]string{"incident", "verify", f}); err != nil {
			t.Fatalf("verify %s: %v", f, err)
		}
	}
	if err := run([]string{"incident", "diff", a, b}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"incident", "diff", a, z, "--json"}); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(a)
	if err := os.WriteFile(a, []byte(strings.Replace(string(raw), `"product": "netra"`, `"product": "other"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"incident", "verify", a}); err == nil {
		t.Fatal("tampered bundle verified")
	}
	if err := run([]string{"incident", "diff", a, b}); err == nil {
		t.Fatal("diff compared a bundle that does not verify")
	}
}

func TestIncidentCommandRejectsBadUsage(t *testing.T) {
	t.Setenv("NETRA_CLI_HELP", "plain")
	srv := httptest.NewServer(http.HandlerFunc(mockNetraAPI))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	for _, args := range [][]string{
		{"incident"}, {"incident", "nope"}, {"incident", "bundle", "--minutes", "0"}, {"incident", "bundle", "--minutes", "x"},
		{"incident", "bundle", "--minutes", "5000"}, {"incident", "bundle", "--bogus"}, {"incident", "bundle", "--mask-ips=maybe"},
		{"incident", "bundle", "--format", "zip"}, {"incident", "bundle", "--format", "tgz"}, {"incident", "bundle", "--out"},
		{"incident", "verify"}, {"incident", "verify", "/nonexistent/file"}, {"incident", "diff", "onlyone"},
	} {
		if err := run(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	empty := filepath.Join(t.TempDir(), "e.json")
	_ = os.WriteFile(empty, nil, 0o600)
	if err := run([]string{"incident", "verify", empty}); err == nil {
		t.Error("empty file verified")
	}
}
