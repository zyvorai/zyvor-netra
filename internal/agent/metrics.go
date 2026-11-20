// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/zyvorai/netra/internal/collectors"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/tsdb"
)

// agentMetrics is the node-local half of the metrics platform: collectors
// write into a tier-0 store, which is streamed to netrad and doubles as the
// replay buffer. See docs/metrics.md.
type agentMetrics struct {
	db     *tsdb.DB
	sched  *collectors.Scheduler
	sender *metricstream.Sender
	latest atomic.Pointer[models.AgentReport]
	// annotate marks anomalous samples before they are stored.
	annotate func([]tsdb.Sample)
}

func (m *agentMetrics) setLatest(r *models.AgentReport) {
	if m != nil {
		m.latest.Store(r)
	}
}

func (m *agentMetrics) sink(samples []tsdb.Sample) {
	if m.annotate != nil {
		m.annotate(samples)
	}
	_, _ = m.db.AppendBatch(samples)
}

// metricsConfig reads the NETRA_METRICS_* environment.
func metricsConfig() (collectors.Config, tsdb.Options) {
	cfg := collectors.Config{
		ProcRoot: env("NETRA_METRICS_PROC", "/proc"),
		SysRoot:  env("NETRA_METRICS_SYS", "/sys"),
		FSRoot:   os.Getenv("NETRA_METRICS_FS_ROOT"),
	}
	if cfg.FSRoot == "" {
		// With hostPID, pid 1's root is the host's root filesystem, so
		// statfs sees host mounts rather than the container overlay.
		if _, err := os.Stat("/proc/1/root/"); err == nil {
			cfg.FSRoot = "/proc/1/root"
		}
	}
	opts := tsdb.Options{
		Dir:            os.Getenv("NETRA_METRICS_AGENT_DIR"),
		Tier0Retention: envDuration("NETRA_METRICS_TIER0_RETENTION", time.Hour),
		MaxSeries:      envInt("NETRA_METRICS_MAX_SERIES", 20000),
	}
	return cfg, opts
}

func envInt(key string, d int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		for _, c := range v {
			if c < '0' || c > '9' {
				return d
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return d
}

func (a *Agent) metricWorkloads() []collectors.Workload {
	ws := a.workloadSnapshot()
	out := make([]collectors.Workload, 0, len(ws))
	for _, w := range ws {
		out = append(out, collectors.Workload{
			Namespace: w.Namespace, Pod: w.Pod, Container: w.ContainerID,
			WorkloadKind: w.WorkloadKind, WorkloadName: w.WorkloadName, CgroupPath: w.CgroupPath,
		})
	}
	return out
}

// startMetrics starts collectors and the stream sender. Off with
// NETRA_METRICS_ENABLED=false.
func (a *Agent) startMetrics(ctx context.Context) {
	if !envBool("NETRA_METRICS_ENABLED", true) {
		return
	}
	cfg, opts := metricsConfig()
	db, err := tsdb.Open(opts)
	if err != nil {
		a.log.Warn("metrics store unavailable; per-second metrics disabled", "error", err)
		return
	}
	m := &agentMetrics{db: db}
	m.annotate = a.newAnomalyAnnotator(ctx, db)
	cs := collectors.Host(cfg)
	cs = append(cs,
		&collectors.Cgroups{List: a.metricWorkloads, Containers: envBool("NETRA_METRICS_CGROUP_CONTAINERS", false)},
		&collectors.Datapath{Latest: m.latest.Load},
		&collectors.WorkloadRED{Latest: m.latest.Load, Max: envInt("NETRA_METRICS_RED_WORKLOADS_MAX", 200)},
	)
	if envBool("NETRA_METRICS_PROCESS_GROUPS", true) {
		cs = append(cs, collectors.NewProcessGroups(cfg, envInt("NETRA_METRICS_PROCESS_GROUPS_MAX", 40)))
	}
	cs = append(cs, a.appCollectors(cfg)...)
	m.sched = collectors.NewScheduler(a.log, m.sink, cs...)
	m.sender = &metricstream.Sender{DB: db, Server: a.server, Node: a.node, Key: a.key, Client: a.http, Log: a.log}
	a.metrics = m
	go m.sched.Run(ctx)
	go m.sender.Run(ctx)
	go db.Run(ctx, 30*time.Second, func(err error) { a.log.Warn("metrics maintenance", "error", err) })
	a.log.Info("per-second metrics started", "collectors", len(cs), "tier0Retention", opts.Tier0Retention.String())
}
