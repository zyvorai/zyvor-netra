// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func newTCPEventsAgent() *Agent {
	return &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), tcpEventsObject: "/nonexistent/netra_tcpevents.o"}
}

func TestReadTCPEventsNilWhenNeverAttached(t *testing.T) {
	if got := newTCPEventsAgent().readTCPEvents(); got != nil {
		t.Fatalf("readTCPEvents = %+v, want nil so the report distinguishes never-attached from attached-but-quiet", got)
	}
}

func TestAttachTCPEventsModes(t *testing.T) {
	t.Run("off skips without error", func(t *testing.T) {
		t.Setenv("NETRA_TCP_EVENTS", "off")
		a := newTCPEventsAgent()
		if err := a.attachTCPEvents(); err != nil || a.tcpEvents != nil {
			t.Fatalf("err = %v, sensor = %v", err, a.tcpEvents)
		}
	})
	t.Run("auto degrades quietly when the object is unavailable", func(t *testing.T) {
		t.Setenv("NETRA_TCP_EVENTS", "auto")
		a := newTCPEventsAgent()
		if err := a.attachTCPEvents(); err != nil || a.tcpEvents != nil {
			t.Fatalf("auto mode must not fail startup: err = %v", err)
		}
	})
	t.Run("default is auto", func(t *testing.T) {
		t.Setenv("NETRA_TCP_EVENTS", "")
		a := newTCPEventsAgent()
		if err := a.attachTCPEvents(); err != nil {
			t.Fatalf("an unset NETRA_TCP_EVENTS must behave as auto, got %v", err)
		}
	})
	t.Run("required fails startup", func(t *testing.T) {
		t.Setenv("NETRA_TCP_EVENTS", "required")
		err := newTCPEventsAgent().attachTCPEvents()
		if err == nil || !strings.Contains(err.Error(), "NETRA_TCP_EVENTS=required") {
			t.Fatalf("err = %v, want it to name the setting", err)
		}
	})
}
