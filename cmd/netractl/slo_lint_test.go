// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSLOLint(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(good, []byte("apiVersion: openslo/v1\nkind: SLO\nmetadata:\n  name: a\n  annotations: {netra.zyvor.dev/sli: http_5xx}\nspec:\n  timeWindow: [{duration: 30d}]\n  objectives: [{target: 0.99}]\n"), 0o600)
	_ = os.WriteFile(bad, []byte("apiVersion: openslo/v1\nkind: SLO\nmetadata: {name: a}\n"), 0o600)
	var out bytes.Buffer
	if err := sloLint(good, &out); err != nil || !strings.Contains(out.String(), `"count": 1`) || !strings.Contains(out.String(), `"targetPct": 99`) {
		t.Fatalf("%v %s", err, out.String())
	}
	if err := sloLint(bad, &out); err == nil {
		t.Fatal("bad file accepted")
	}
	if err := sloLint(filepath.Join(dir, "nope.yaml"), &out); err == nil {
		t.Fatal("missing file accepted")
	}
}
