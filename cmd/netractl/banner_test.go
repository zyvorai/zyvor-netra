// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"os"
	"strings"
	"testing"
)

func TestPrintBannerContainsNetra(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "dumb")
	f, err := os.CreateTemp("", "netra-banner-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	defer os.Remove(path)
	printBanner(f)
	_ = f.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := stripANSI(string(b))
	if !strings.Contains(out, "Netra") {
		t.Fatalf("banner missing Netra: %q", out)
	}
	if !strings.Contains(out, "Zyvor") {
		t.Fatalf("banner missing Zyvor: %q", out)
	}
	if !strings.Contains(out, "observe") {
		t.Fatalf("banner missing tagline: %q", out)
	}
}
