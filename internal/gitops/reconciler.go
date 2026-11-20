// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package gitops

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

// Config controls the reconciler's poll cadence and source directory.
type Config struct {
	// Dir is NETRA_GITOPS_DIR — required; Reconciler.Run does nothing
	// useful with an empty Dir (every tick just reports a load error).
	Dir string
	// AutoApply is NETRA_GITOPS_AUTO_APPLY, default false. See Reconcile's
	// doc comment for exactly what false vs. true changes.
	AutoApply bool
	// Interval between reconcile passes. Default 60s.
	Interval time.Duration
}

func (c *Config) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = 60 * time.Second
	}
}

// Reconciler periodically loads and reconciles NETRA_GITOPS_DIR, caching
// the latest status for GET /api/v1/policies/gitops/status to read without
// itself doing any I/O. Constructed and run only between gate.Promote and
// gate.Demote in cmd/netrad/main.go's electionLoop (or, for a single
// non-HA replica, main's direct startup path) — the same cancellation
// lifecycle internal/alert.Poller already uses there. No second
// leader-election mechanism: whichever process already holds write access
// to *store.Store is the only one ever running a Reconciler.
type Reconciler struct {
	log   *slog.Logger
	kube  *kube.Client
	store *store.Store
	cfg   Config

	mu     sync.RWMutex
	status models.GitOpsStatusResponse
}

func New(log *slog.Logger, k *kube.Client, st *store.Store, cfg Config) *Reconciler {
	cfg.applyDefaults()
	return &Reconciler{log: log, kube: k, store: st, cfg: cfg}
}

// Run blocks until ctx is cancelled, reconciling at cfg.Interval. It
// reconciles once immediately before the first tick, mirroring
// internal/alert.Poller.Run's own identical pattern.
func (r *Reconciler) Run(ctx context.Context) {
	r.tick(ctx)
	t := time.NewTicker(r.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *Reconciler) tick(ctx context.Context) {
	manifests, loadErrors := LoadManifests(r.cfg.Dir)
	statuses := Reconcile(ctx, r.kube, r.store, manifests, r.cfg.AutoApply)
	r.mu.Lock()
	r.status = models.GitOpsStatusResponse{LastRun: time.Now().UTC(), Dir: r.cfg.Dir, AutoApply: r.cfg.AutoApply, Manifests: statuses, LoadErrors: loadErrors}
	r.mu.Unlock()
	for _, e := range loadErrors {
		r.log.Warn("gitops manifest load error", "error", e)
	}
	for _, s := range statuses {
		if s.Error != "" {
			r.log.Warn("gitops reconcile error", "path", s.Path, "namespace", s.Namespace, "name", s.Name, "error", s.Error)
		}
		if s.Applied {
			r.log.Info("gitops applied", "path", s.Path, "namespace", s.Namespace, "name", s.Name)
		}
		if s.Drifted {
			r.log.Warn("gitops drift detected", "path", s.Path, "namespace", s.Namespace, "name", s.Name)
		}
	}
}

// Status returns the most recent reconcile pass's cached result. Safe for
// concurrent use with Run.
func (r *Reconciler) Status() models.GitOpsStatusResponse {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

// Resync is the explicit human override — see the package-level Resync's
// doc comment for what it does and why it bypasses Reconcile's own
// auto-apply gating.
func (r *Reconciler) Resync(ctx context.Context, candidate []byte, confirmedRisk string) (models.ChangePlanRef, error) {
	return Resync(ctx, r.kube, r.store, candidate, confirmedRisk)
}
