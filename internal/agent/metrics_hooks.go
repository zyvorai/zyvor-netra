// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"context"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/collectors"
	"github.com/zyvorai/netra/internal/tsdb"
)

// newAnomalyAnnotator trains per-dimension models on this node's tier-0
// store and marks anomalous samples before they are stored and streamed.
// Off with NETRA_METRICS_ML=false; netrad can then score instead
// (NETRA_METRICS_PARENT_ML=true).
func (a *Agent) newAnomalyAnnotator(ctx context.Context, db *tsdb.DB) func([]tsdb.Sample) {
	if !envBool("NETRA_METRICS_ML", true) {
		return nil
	}
	det := anomaly.New(anomaly.Options{
		TrainWindow: envDuration("NETRA_METRICS_ML_TRAIN_WINDOW", time.Hour),
		TrainEvery:  envDuration("NETRA_METRICS_ML_TRAIN_EVERY", 30*time.Minute),
	})
	go det.Run(ctx, db)
	return det.Annotate
}

// appCollectors scrapes applications listed in NETRA_APPS_CONFIG (default
// /etc/netra/apps.yaml) and, with NETRA_APPS_DISCOVERY=true, ones found
// listening in the host network namespace. Credentials come only from
// environment variables named in that config.
func (a *Agent) appCollectors(cfg collectors.Config) []collectors.Collector {
	static, err := collectors.LoadAppsConfig(env("NETRA_APPS_CONFIG", "/etc/netra/apps.yaml"))
	if err != nil {
		a.log.Warn("apps config ignored", "error", err)
		static = nil
	}
	discover := envBool("NETRA_APPS_DISCOVERY", false)
	if len(static) == 0 && !discover {
		return nil
	}
	return []collectors.Collector{collectors.NewApps(cfg, static, discover, envDuration("NETRA_APPS_EVERY", 5*time.Second), a.log)}
}
