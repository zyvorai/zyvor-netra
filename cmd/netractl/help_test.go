// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintUsageReadable(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("NETRA_CLI_NO_BANNER", "1")
	t.Setenv("TERM", "dumb")
	var buf bytes.Buffer
	printUsage(&buf)
	out := stripANSI(buf.String())
	for _, need := range []string{"Usage", "Cluster", "status", "features", "Environment", "NETRA_URL", "🚀", "🔍"} {
		if !strings.Contains(out, need) {
			t.Fatalf("missing %q in help:\n%s", need, out)
		}
	}
	// Should not be one giant unbroken line of every ebpf subcommand.
	if strings.Count(out, "\n") < 20 {
		t.Fatalf("help too dense (%d lines)", strings.Count(out, "\n"))
	}
}

func TestHelpSectionsNonEmpty(t *testing.T) {
	secs := helpSections()
	if len(secs) < 4 {
		t.Fatalf("expected grouped sections, got %d", len(secs))
	}
	for _, s := range secs {
		if s.title == "" || len(s.cmds) == 0 {
			t.Fatalf("bad section %+v", s)
		}
	}
}
