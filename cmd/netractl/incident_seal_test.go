// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncidentSealCLI(t *testing.T) {
	t.Setenv("NETRA_CLI_HELP", "plain")
	bundle := writeCLIFixture(t, "bundle")
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("a-sixteen-plus-byte-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seal := filepath.Join(dir, "b.seal")
	if err := run([]string{"incident", "seal", bundle, "--key-file", key, "--out", seal}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(seal); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("seal missing or not 0600: %v", st)
	}
	if raw, _ := os.ReadFile(seal); strings.Contains(string(raw), "sixteen") {
		t.Fatal("seal contains key material")
	}
	if err := run([]string{"incident", "verify", bundle, "--seal", seal, "--key-file", key}); err != nil {
		t.Fatalf("good seal: %v", err)
	}
	// Wrong key.
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("a-different-long-key-1"), 0o600)
	if err := run([]string{"incident", "verify", bundle, "--seal", seal, "--key-file", bad}); err == nil {
		t.Fatal("wrong key accepted")
	}
	// Short key and missing key are refused.
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("tiny"), 0o600)
	if err := run([]string{"incident", "seal", bundle, "--key-file", short}); err == nil {
		t.Fatal("short key accepted")
	}
	t.Setenv("NETRA_INCIDENT_SEAL_KEY", "")
	if err := run([]string{"incident", "seal", bundle}); err == nil {
		t.Fatal("missing key accepted")
	}
	// Report to a file.
	out := filepath.Join(dir, "r.md")
	if err := run([]string{"incident", "report", bundle, "--out", out}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(out); !strings.Contains(string(raw), "# Incident report draft") {
		t.Fatalf("report: %s", raw)
	}
	// A tampered bundle yields no report.
	raw, _ := os.ReadFile(bundle)
	_ = os.WriteFile(bundle, []byte(strings.Replace(string(raw), `"observe"`, `"enforce"`, 1)), 0o600)
	if err := run([]string{"incident", "report", bundle}); err == nil {
		t.Fatal("report from tampered bundle")
	}
}
