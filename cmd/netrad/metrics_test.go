// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildMetricsWiresAlertsAndExporters(t *testing.T) {
	t.Setenv("NETRA_METRICS_ENABLED", "true")
	t.Setenv("NETRA_METRICS_DIR", "-")
	t.Setenv("NETRA_METRICALERT_DIR", t.TempDir())
	t.Setenv("NETRA_EXPORT_PROMETHEUS_RW_URL", "http://127.0.0.1:1/api/v1/write")
	t.Setenv("NETRA_EXPORT_GRAPHITE_ADDR", "127.0.0.1:2003")
	t.Setenv("NETRA_EXPORT_RESOLUTION", "30s")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := buildMetrics(log, filepath.Join(t.TempDir(), "state.json"), nil)
	if m == nil || m.hubOrNil() == nil {
		t.Fatal("metrics runtime not built")
	}
	if m.alertsOrNil() == nil {
		t.Fatal("metric alerts not built")
	}
	st := m.exporterStatus()
	if len(st) != 2 || st[0].Sink != "prometheus-remote-write" || st[1].Sink != "graphite" || st[0].Resolution != "30s" {
		t.Fatalf("exporters %+v", st)
	}
}

func TestBuildMetricsDisabled(t *testing.T) {
	t.Setenv("NETRA_METRICS_ENABLED", "false")
	m := buildMetrics(slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil)
	if m != nil || m.hubOrNil() != nil || m.alertsOrNil() != nil || m.exporterStatus() != nil {
		t.Fatal("disabled metrics should be a nil runtime with nil-safe accessors")
	}
}

func TestBuildMetricsBadRulesDisableAlertsOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NETRA_METRICS_DIR", "-")
	t.Setenv("NETRA_METRICALERT_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("alerts:\n  - alarm: x\n    on: y\n    lookup: nonsense\n    warn: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := buildMetrics(slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil)
	if m == nil || m.alertsOrNil() != nil {
		t.Fatal("invalid rules should disable alerts but keep metrics")
	}
}
