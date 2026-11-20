// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/metricalert"
	"github.com/zyvorai/netra/internal/metricexport"
	"github.com/zyvorai/netra/internal/metricstream"
	"github.com/zyvorai/netra/internal/notify"
	"github.com/zyvorai/netra/internal/tsdb"
)

// metricsRuntime is the parent half of the per-second metrics platform. It is
// built per leadership stint in HA mode so only the leader writes.
type metricsRuntime struct {
	log       *slog.Logger
	hub       *metricstream.Hub
	ml        *parentML
	alerts    *metricalert.Engine
	exporters []*metricexport.Exporter
}

// buildMetrics opens the per-node metrics stores. It returns nil when
// NETRA_METRICS_ENABLED=false or the stores cannot be opened.
func buildMetrics(log *slog.Logger, stateFile string, dispatcher *notify.Dispatcher) *metricsRuntime {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_METRICS_ENABLED")), "false") {
		return nil
	}
	dir := strings.TrimSpace(os.Getenv("NETRA_METRICS_DIR"))
	if dir == "" && stateFile != "" {
		dir = filepath.Join(filepath.Dir(stateFile), "metrics")
	}
	if dir == "-" {
		dir = ""
	}
	hub, err := metricstream.OpenHub(metricstream.HubOptions{
		Dir: dir,
		DB: tsdb.Options{
			Tier0Retention: envDuration("NETRA_METRICS_TIER0_RETENTION", time.Hour),
			Tier1Retention: envDuration("NETRA_METRICS_TIER1_RETENTION", 14*24*time.Hour),
			Tier2Retention: envDuration("NETRA_METRICS_TIER2_RETENTION", 365*24*time.Hour),
			DiskQuotaBytes: int64(envInt("NETRA_METRICS_DISK_QUOTA_MB", 1024)) << 20,
			MaxSeries:      envInt("NETRA_METRICS_MAX_SERIES", 50000),
		},
		MaxNodes: envInt("NETRA_METRICS_MAX_NODES", 2000),
		Log:      log,
	})
	if err != nil {
		log.Error("metrics store unavailable; per-second metrics disabled", "dir", dir, "error", err)
		return nil
	}
	log.Info("per-second metrics enabled", "dir", dir)
	m := &metricsRuntime{log: log, hub: hub}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_METRICS_PARENT_ML")), "true") {
		m.ml = &parentML{dets: map[string]*anomaly.Detector{}}
		hub.Annotate = m.ml.annotate
	}
	m.alerts = buildMetricAlerts(log, hub, dir, dispatcher)
	m.exporters = buildExporters(log, hub)
	return m
}

// buildExporters reads NETRA_EXPORT_*. Credentials come from these
// variables only (typically a Secret mounted as env by the operator).
func buildExporters(log *slog.Logger, hub *metricstream.Hub) []*metricexport.Exporter {
	res := envDuration("NETRA_EXPORT_RESOLUTION", 10*time.Second)
	split := func(k string) []string {
		var out []string
		for _, f := range strings.Split(os.Getenv(k), ",") {
			if f = strings.TrimSpace(f); f != "" {
				out = append(out, f)
			}
		}
		return out
	}
	prefix := strings.TrimSpace(os.Getenv("NETRA_EXPORT_PREFIX"))
	var sinks []metricexport.Sink
	if u := strings.TrimSpace(os.Getenv("NETRA_EXPORT_PROMETHEUS_RW_URL")); u != "" {
		sinks = append(sinks, &metricexport.RemoteWrite{URL: u, Headers: metricexport.ParseHeaders(os.Getenv("NETRA_EXPORT_PROMETHEUS_RW_HEADERS")), Prefix: prefix})
	}
	if u := strings.TrimSpace(os.Getenv("NETRA_EXPORT_OTLP_ENDPOINT")); u != "" {
		resAttrs := map[string]string{}
		if c := strings.TrimSpace(os.Getenv("NETRA_CLUSTER_NAME")); c != "" {
			resAttrs["k8s.cluster.name"] = c
		}
		sinks = append(sinks, &metricexport.OTLP{Endpoint: u, Headers: metricexport.ParseHeaders(os.Getenv("NETRA_EXPORT_OTLP_HEADERS")), Prefix: prefix, Resource: resAttrs})
	}
	if a := strings.TrimSpace(os.Getenv("NETRA_EXPORT_GRAPHITE_ADDR")); a != "" {
		sinks = append(sinks, &metricexport.Graphite{Addr: a, Prefix: prefix})
	}
	var out []*metricexport.Exporter
	for _, s := range sinks {
		e, err := metricexport.New(metricexport.Options{
			Sources: hub.Sources, Sink: s, Resolution: res,
			Contexts: split("NETRA_EXPORT_CONTEXTS"), Exclude: split("NETRA_EXPORT_EXCLUDE"), Log: log,
		})
		if err != nil {
			log.Error("metrics exporter disabled", "sink", s.Name(), "error", err)
			continue
		}
		log.Info("metrics exporter enabled", "sink", s.Name(), "resolution", res.String())
		out = append(out, e)
	}
	return out
}

func (m *metricsRuntime) exporterStatus() []metricexport.Status {
	if m == nil {
		return nil
	}
	out := make([]metricexport.Status, 0, len(m.exporters))
	for _, e := range m.exporters {
		out = append(out, e.Status())
	}
	return out
}

// buildMetricAlerts loads the built-in rule pack plus NETRA_METRICALERT_DIR
// and publishes transitions through the alert dispatcher when one is
// configured. Off with NETRA_METRICALERT_ENABLED=false.
func buildMetricAlerts(log *slog.Logger, hub *metricstream.Hub, dir string, dispatcher *notify.Dispatcher) *metricalert.Engine {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_METRICALERT_ENABLED")), "false") {
		return nil
	}
	ruleDir := strings.TrimSpace(os.Getenv("NETRA_METRICALERT_DIR"))
	if ruleDir == "" {
		ruleDir = "/etc/netra/metricalert.d"
	}
	defaults := !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_METRICALERT_DEFAULTS")), "false")
	rules, err := metricalert.LoadRules(defaults, ruleDir)
	if err != nil {
		log.Error("metric alert rules invalid; metric alerts disabled", "dir", ruleDir, "error", err)
		return nil
	}
	opts := metricalert.Options{Rules: rules, Sources: hub.Sources, Log: log}
	if dir != "" {
		opts.SilenceFile = filepath.Join(dir, "metricalert-silences.json")
	}
	if dispatcher != nil {
		opts.Publish = dispatcher.Publish
	}
	eng, err := metricalert.New(opts)
	if err != nil {
		log.Error("metric alert rules invalid; metric alerts disabled", "dir", ruleDir, "error", err)
		return nil
	}
	log.Info("metric alerts enabled", "rules", len(rules), "dir", ruleDir, "notify", dispatcher != nil)
	return eng
}

func (m *metricsRuntime) alertsOrNil() *metricalert.Engine {
	if m == nil {
		return nil
	}
	return m.alerts
}

// parentML scores streamed samples on netrad, for agents that run with
// NETRA_METRICS_ML=false. A sample already marked by its agent stays marked.
type parentML struct {
	mu   sync.Mutex
	dets map[string]*anomaly.Detector
}

func (p *parentML) detector(node string) *anomaly.Detector {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.dets[node]
	if d == nil {
		d = anomaly.New(anomaly.Options{})
		p.dets[node] = d
	}
	return d
}

func (p *parentML) annotate(node string, samples []tsdb.Sample) {
	p.detector(node).Annotate(samples)
}

func (p *parentML) run(ctx context.Context, hub *metricstream.Hub) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, src := range hub.Sources() {
				p.detector(src.Node).TrainDue(src.DB, now, 200)
			}
		}
	}
}

func (m *metricsRuntime) hubOrNil() *metricstream.Hub {
	if m == nil {
		return nil
	}
	return m.hub
}

// start runs maintenance until the returned stop is called; stop also
// flushes and closes the stores.
func (m *metricsRuntime) start(ctx context.Context, wg *sync.WaitGroup) func() {
	if m == nil {
		return nil
	}
	mctx, cancel := context.WithCancel(ctx)
	var inner sync.WaitGroup
	inner.Add(1)
	go func() {
		defer inner.Done()
		m.hub.Run(mctx, 10*time.Second)
	}()
	for _, e := range m.exporters {
		inner.Add(1)
		go func() {
			defer inner.Done()
			e.Run(mctx)
		}()
	}
	if m.alerts != nil {
		inner.Add(1)
		go func() {
			defer inner.Done()
			m.alerts.Run(mctx)
		}()
	}
	if m.ml != nil {
		inner.Add(1)
		go func() {
			defer inner.Done()
			m.ml.run(mctx, m.hub)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-mctx.Done()
		inner.Wait()
		if err := m.hub.Close(); err != nil {
			m.log.Warn("close metrics stores", "error", err)
		}
	}()
	return cancel
}
