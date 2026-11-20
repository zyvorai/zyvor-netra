// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func newDropInfoAgent() *Agent {
	return &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), dropInfoObject: "/nonexistent/netra_dropinfo.o"}
}

func TestReadDropInfoNilWhenNeverTried(t *testing.T) {
	if got := newDropInfoAgent().readDropInfo(); got != nil {
		t.Fatalf("readDropInfo = %+v, want nil so the report distinguishes off from unavailable", got)
	}
}

func TestAttachDropInfoModes(t *testing.T) {
	t.Run("off skips without error and reports nothing", func(t *testing.T) {
		t.Setenv("NETRA_DROP_INFO", "off")
		a := newDropInfoAgent()
		if err := a.attachDropInfo(); err != nil || a.dropInfo != nil {
			t.Fatalf("err = %v, sensor = %v", err, a.dropInfo)
		}
		if a.readDropInfo() != nil {
			t.Fatal("an operator who turned it off must not see an 'unavailable' report")
		}
	})
	t.Run("auto degrades and says why", func(t *testing.T) {
		t.Setenv("NETRA_DROP_INFO", "auto")
		a := newDropInfoAgent()
		if err := a.attachDropInfo(); err != nil || a.dropInfo != nil {
			t.Fatalf("auto mode must not fail startup: err = %v", err)
		}
		got := a.readDropInfo()
		if got == nil || got.Attached || got.Unavailable == "" {
			t.Fatalf("report = %+v, want an unattached summary carrying the reason", got)
		}
	})
	t.Run("the reason is bounded", func(t *testing.T) {
		a := newDropInfoAgent()
		a.dropInfoWhy = strings.Repeat("x", 5000)
		if got := a.readDropInfo(); len(got.Unavailable) != maxWhy {
			t.Fatalf("reason is %d bytes, want it cut to %d", len(got.Unavailable), maxWhy)
		}
	})
	t.Run("default is auto", func(t *testing.T) {
		t.Setenv("NETRA_DROP_INFO", "")
		if err := newDropInfoAgent().attachDropInfo(); err != nil {
			t.Fatalf("an unset NETRA_DROP_INFO must behave as auto, got %v", err)
		}
	})
	t.Run("required fails startup", func(t *testing.T) {
		t.Setenv("NETRA_DROP_INFO", "required")
		err := newDropInfoAgent().attachDropInfo()
		if err == nil || !strings.Contains(err.Error(), "NETRA_DROP_INFO=required") {
			t.Fatalf("err = %v, want it to name the setting", err)
		}
	})
}
