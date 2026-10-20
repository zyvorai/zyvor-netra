// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestURLIsLoopback(t *testing.T) {
	if !urlIsLoopback("https://127.0.0.1:30870") {
		t.Fatal("127.0.0.1")
	}
	if !urlIsLoopback("https://localhost:30870/api") {
		t.Fatal("localhost")
	}
	if urlIsLoopback("https://212.8.248.187:30870") {
		t.Fatal("public IP should not be loopback")
	}
}

func TestLoadEnvFileDoesNotOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	if err := os.WriteFile(path, []byte("NETRA_TLS_INSECURE=true\nNETRA_URL=https://example.test:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETRA_URL", "https://keep.example:9")
	t.Setenv("NETRA_TLS_INSECURE", "")
	loadEnvFile(path)
	if os.Getenv("NETRA_URL") != "https://keep.example:9" {
		t.Fatalf("overrode NETRA_URL: %s", os.Getenv("NETRA_URL"))
	}
	if os.Getenv("NETRA_TLS_INSECURE") != "true" {
		t.Fatalf("expected TLS insecure from file, got %q", os.Getenv("NETRA_TLS_INSECURE"))
	}
}

func TestTLSInsecureLoopbackDefault(t *testing.T) {
	t.Setenv("NETRA_TLS_INSECURE", "")
	oldBase := base
	t.Cleanup(func() { base = oldBase })
	base = "https://127.0.0.1:30870"
	if !tlsInsecure() {
		t.Fatal("expected loopback insecure when unset")
	}
	t.Setenv("NETRA_TLS_INSECURE", "false")
	if tlsInsecure() {
		t.Fatal("explicit false must win")
	}
}
