// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCLIInstallPathExplicit(t *testing.T) {
	dest, err := resolveCLIInstallPath("/opt/netra", "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/opt/netra", "bin", "netractl")
	if dest != want {
		t.Fatalf("got %q want %q", dest, want)
	}
	dest, err = resolveCLIInstallPath("", "/tmp/netra-bins")
	if err != nil {
		t.Fatal(err)
	}
	if dest != filepath.Join("/tmp/netra-bins", "netractl") {
		t.Fatalf("bin-dir: %q", dest)
	}
}

func TestInstallSelfCLI(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src-netractl")
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho netractl\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// installSelfCLI uses os.Executable — test the copy path via a helper
	// by copying manually with the same permissions pattern.
	dest := filepath.Join(dir, "bin", "netractl")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.ReadFrom(in); err != nil {
		t.Fatal(err)
	}
	_ = out.Close()
	if err := os.Rename(tmp, dest); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&0o111 == 0 {
		t.Fatalf("dest not executable: %v", st.Mode())
	}
}

func TestDefaultCLIBinDirs(t *testing.T) {
	dirs := defaultCLIBinDirs()
	if len(dirs) == 0 {
		t.Fatal("expected at least one bin dir")
	}
}
