// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"io"
	"log/slog"
	"testing"
)

// TestReadEdgeIntelNilWhenNeverAttached guards models.EdgeIntelSummary's
// documented nil-vs-attached-but-quiet distinction: a node where edge
// intel never attached must report nil, not an empty-but-present summary.
func TestReadEdgeIntelNilWhenNeverAttached(t *testing.T) {
	a := &Agent{}
	got, err := a.readEdgeIntel()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil EdgeIntelSummary when edgeCollection is nil, got %+v", got)
	}
}

// TestAttachEdgeIntelOffSkipsWithoutTouchingObject confirms
// NETRA_EDGE_INTEL=off never attempts to load the BPF object at all — a
// bogus/missing edgeObject path must not produce an error in this mode.
func TestAttachEdgeIntelOffSkipsWithoutTouchingObject(t *testing.T) {
	t.Setenv("NETRA_EDGE_INTEL", "off")
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), edgeObject: "/nonexistent/path/does-not-exist.o"}
	if err := a.attachEdgeIntel(nil); err != nil {
		t.Fatalf("NETRA_EDGE_INTEL=off should skip cleanly, got error: %v", err)
	}
	if a.edgeCollection != nil {
		t.Fatal("expected no edge collection to be loaded when NETRA_EDGE_INTEL=off")
	}
}

// TestAttachEdgeIntelAutoToleratesMissingObject confirms the auto-mode
// (default) behavior: a missing object file is a warning, not a fatal
// agent-startup error — this is a newer, optional feature.
func TestAttachEdgeIntelAutoToleratesMissingObject(t *testing.T) {
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), edgeObject: "/nonexistent/path/does-not-exist.o"}
	if err := a.attachEdgeIntel(nil); err != nil {
		t.Fatalf("NETRA_EDGE_INTEL=auto (default) should tolerate a missing object, got error: %v", err)
	}
}

// TestAttachEdgeIntelRequiredFailsOnMissingObject confirms the opposite:
// an operator who explicitly opted into NETRA_EDGE_INTEL=required gets a
// real startup failure, not a silent skip.
func TestAttachEdgeIntelRequiredFailsOnMissingObject(t *testing.T) {
	t.Setenv("NETRA_EDGE_INTEL", "required")
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), edgeObject: "/nonexistent/path/does-not-exist.o"}
	if err := a.attachEdgeIntel(nil); err == nil {
		t.Fatal("expected an error for a missing object under NETRA_EDGE_INTEL=required")
	}
}
