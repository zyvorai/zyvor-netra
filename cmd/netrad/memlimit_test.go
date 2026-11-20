// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestParseCgroupLimit(t *testing.T) {
	for in, want := range map[string]struct {
		n  uint64
		ok bool
	}{
		"268435456\n":         {268435456, true}, // 256Mi
		"  536870912  ":       {536870912, true}, // 512Mi
		"max\n":               {0, false},        // cgroup v2, unlimited
		"9223372036854771712": {0, false},        // cgroup v1, unlimited
		"":                    {0, false},
		"garbage":             {0, false},
		"-5":                  {0, false},
		"1048576":             {0, false}, // 1Mi: not a plausible container limit
	} {
		if n, ok := parseCgroupLimit(in); n != want.n || ok != want.ok {
			t.Errorf("parseCgroupLimit(%q) = %d, %v; want %d, %v", in, n, ok, want.n, want.ok)
		}
	}
}

func TestCgroupMemoryLimitPrefersV2ThenFallsBackToV1(t *testing.T) {
	v2 := t.TempDir()
	_ = os.WriteFile(filepath.Join(v2, "memory.max"), []byte("268435456\n"), 0o644)
	if n, ok := cgroupMemoryLimit(v2); !ok || n != 268435456 {
		t.Fatalf("v2 = %d, %v", n, ok)
	}

	v1 := t.TempDir()
	_ = os.MkdirAll(filepath.Join(v1, "memory"), 0o755)
	_ = os.WriteFile(filepath.Join(v1, "memory", "memory.limit_in_bytes"), []byte("536870912\n"), 0o644)
	if n, ok := cgroupMemoryLimit(v1); !ok || n != 536870912 {
		t.Fatalf("v1 = %d, %v", n, ok)
	}

	unlimited := t.TempDir()
	_ = os.WriteFile(filepath.Join(unlimited, "memory.max"), []byte("max\n"), 0o644)
	if _, ok := cgroupMemoryLimit(unlimited); ok {
		t.Fatal("an unlimited cgroup must yield no limit")
	}
	if _, ok := cgroupMemoryLimit(t.TempDir()); ok {
		t.Fatal("no cgroup files must yield no limit")
	}
}

// An explicit GOMEMLIMIT is the operator's choice and must win.
func TestApplyMemoryLimitLeavesAnExplicitGOMEMLIMITAlone(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "123MiB")
	before := debug.SetMemoryLimit(-1)
	applyMemoryLimit(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if after := debug.SetMemoryLimit(-1); after != before {
		t.Fatalf("limit changed from %d to %d although GOMEMLIMIT was set", before, after)
	}
}
