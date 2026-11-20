// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package gitops

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/store"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestReconcilerTickPopulatesStatus(t *testing.T) {
	k, _ := newFakeKube(t)
	st := store.New()
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: a\n  namespace: prod\nspec:\n  endpointSelector:\n    matchLabels:\n      app: a\n  egress:\n  - toCIDR: [\"10.0.0.0/24\"]\n")

	r := New(discardLogger(), k, st, Config{Dir: dir, AutoApply: true})
	r.tick(context.Background())

	status := r.Status()
	if status.Dir != dir || !status.AutoApply {
		t.Fatalf("status=%#v", status)
	}
	if len(status.Manifests) != 1 || !status.Manifests[0].Applied {
		t.Fatalf("manifests=%#v, want one applied manifest", status.Manifests)
	}
}

func TestReconcilerStatusEmptyBeforeFirstTick(t *testing.T) {
	k, _ := newFakeKube(t)
	st := store.New()
	r := New(discardLogger(), k, st, Config{Dir: t.TempDir()})
	status := r.Status()
	if status.LastRun.After(time.Now()) || !status.LastRun.IsZero() {
		t.Fatalf("expected a zero-value status before any tick, got %#v", status)
	}
}

func TestReconcilerRunStopsOnContextCancel(t *testing.T) {
	k, _ := newFakeKube(t)
	st := store.New()
	r := New(discardLogger(), k, st, Config{Dir: t.TempDir(), Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
