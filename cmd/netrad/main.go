// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zyvorai/netra/internal/alert"
	"github.com/zyvorai/netra/internal/api"
	"github.com/zyvorai/netra/internal/automitigate"
	"github.com/zyvorai/netra/internal/capture"
	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/gitops"
	"github.com/zyvorai/netra/internal/ha"
	"github.com/zyvorai/netra/internal/hubble"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/lokipush"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/mtls"
	"github.com/zyvorai/netra/internal/notify"
	"github.com/zyvorai/netra/internal/oidcauth"
	"github.com/zyvorai/netra/internal/otlppush"
	"github.com/zyvorai/netra/internal/pushfeed"
	"github.com/zyvorai/netra/internal/scandetect"
	"github.com/zyvorai/netra/internal/siem"
	"github.com/zyvorai/netra/internal/snowflakesink"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/sysctlaudit"
	"github.com/zyvorai/netra/internal/workloadobs"
)

const version = "0.29.0"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	applyMemoryLimit(log)
	allowUnauthenticated := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_ALLOW_UNAUTHENTICATED")), "true")
	if !allowUnauthenticated {
		if strings.TrimSpace(os.Getenv("NETRA_API_KEY")) == "" || strings.TrimSpace(os.Getenv("NETRA_AGENT_KEY")) == "" {
			log.Error("secure startup refused", "reason", "NETRA_API_KEY and NETRA_AGENT_KEY are required unless NETRA_ALLOW_UNAUTHENTICATED=true")
			os.Exit(1)
		}
	} else {
		log.Warn("unauthenticated development mode enabled")
	}

	// Refuse a bad mTLS setting now, before anything starts, not on the first agent.
	if _, _, err := mtls.FromEnv(tlsConfigured()); err != nil {
		log.Error("secure startup refused", "reason", err.Error())
		os.Exit(1)
	}

	k, err := kube.NewFromEnvironment()
	if err != nil {
		log.Error("kubernetes client", "error", err)
		os.Exit(1)
	}
	h, err := hubble.NewFromEnvironment()
	if err != nil {
		log.Error("hubble client", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dispatcher, alertCfg := buildAlerting(log)
	if dispatcher != nil {
		dispatcher.Start(envInt("NETRA_ALERT_WORKERS", 2))
		defer dispatcher.Stop()
	}
	artifacts := buildArtifactStore(log)
	gitopsCfg, gitopsEnabled := buildGitOps()

	stateFile := strings.TrimSpace(os.Getenv("NETRA_STATE_FILE"))
	haEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_HA_ENABLED")), "true")
	if haEnabled {
		if stateFile == "" {
			log.Error("HA startup refused", "reason", "NETRA_STATE_FILE is required in HA mode")
			os.Exit(1)
		}
		runHA(ctx, log, k, h, stateFile, dispatcher, alertCfg, artifacts, gitopsCfg, gitopsEnabled)
		return
	}

	st, err := store.Open(stateFile)
	if err != nil {
		log.Error("state store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	var gr *gitops.Reconciler
	if gitopsEnabled {
		gr = gitops.New(log, k, st, gitopsCfg)
	}
	dnsDet, dnsInterval, dnsEnabled := buildDNSDetect()
	scanDet, scanInterval, scanEnabled := buildScanDetect()
	autoEng, autoEnabled := buildAutoMitigate(log, st, scanDet)
	wobs := buildWorkloadObs(log)
	metrics := buildMetrics(log, stateFile, dispatcher)
	handler := api.New(log, k, h, st).WithOIDC(buildOIDC(log)).WithWorkloadObs(wobs).WithGitOps(gr).WithDNSDetect(dnsDet).WithScanDetect(scanDet).WithAutoMitigate(autoEng).WithArtifacts(artifacts).WithMetrics(metrics.hubOrNil()).WithMetricAlerts(metrics.alertsOrNil()).WithMetricExporters(metrics.exporterStatus).Handler()
	var metricsWG sync.WaitGroup
	if stop := metrics.start(ctx, &metricsWG); stop != nil {
		defer metricsWG.Wait()
		defer stop()
	}

	if shouldRunAlertPoller(dispatcher) {
		var pollerWG sync.WaitGroup
		pctx, cancel := context.WithCancel(ctx)
		defer cancel()
		pollerWG.Add(1)
		go func() {
			defer pollerWG.Done()
			newAlertPoller(log, st, dispatcher, alertCfg, k.ListPods, artifacts).Run(pctx)
		}()
		defer pollerWG.Wait()
	}
	if gr != nil {
		var gitopsWG sync.WaitGroup
		gctx, cancel := context.WithCancel(ctx)
		defer cancel()
		gitopsWG.Add(1)
		go func() {
			defer gitopsWG.Done()
			gr.Run(gctx)
		}()
		defer gitopsWG.Wait()
	}
	var syslogWG sync.WaitGroup
	if stop := startSyslog(ctx, log, st, &syslogWG); stop != nil {
		defer stop()
		defer syslogWG.Wait()
	}
	var snowflakeWG sync.WaitGroup
	if stop := startSnowflake(ctx, log, st, &snowflakeWG); stop != nil {
		defer stop()
		defer snowflakeWG.Wait()
	}
	var otlpWG sync.WaitGroup
	if stop := startOTLP(ctx, log, st, handler, &otlpWG); stop != nil {
		defer stop()
		defer otlpWG.Wait()
	}
	var wobsWG sync.WaitGroup
	if stop := startWorkloadObs(ctx, log, st, wobs, &wobsWG); stop != nil {
		defer stop()
		defer wobsWG.Wait()
	}
	var lokiWG sync.WaitGroup
	if stop := startLoki(ctx, log, st, &lokiWG); stop != nil {
		defer stop()
		defer lokiWG.Wait()
	}
	staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
	if dnsEnabled {
		var dnsWG sync.WaitGroup
		dctx, cancel := context.WithCancel(ctx)
		defer cancel()
		dnsWG.Add(1)
		go func() {
			defer dnsWG.Done()
			log.Info("dns-detect started", "interval", dnsInterval)
			dnsDet.Run(dctx, dnsInterval, func() []models.AgentStatus { return st.AgentStatuses(time.Now(), staleAfter) })
		}()
		defer dnsWG.Wait()
	}
	if scanEnabled {
		var scanWG sync.WaitGroup
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		scanWG.Add(1)
		go func() {
			defer scanWG.Done()
			log.Info("scan-detect started", "interval", scanInterval)
			scanDet.Run(sctx, scanInterval, func() []models.AgentStatus { return st.AgentStatuses(time.Now(), staleAfter) })
		}()
		defer scanWG.Wait()
	}
	if autoEnabled {
		var autoWG sync.WaitGroup
		actx, cancel := context.WithCancel(ctx)
		defer cancel()
		autoWG.Add(1)
		go func() {
			defer autoWG.Done()
			log.Info("auto-mitigate started")
			autoEng.Run(actx, func() []models.AgentStatus { return st.AgentStatuses(time.Now(), staleAfter) })
		}()
		defer autoWG.Wait()
	}

	runHTTP(ctx, log, handler, st.Persistent(), false)
}

// startSyslog starts the optional RFC5424/CEF/JSONL push sink when
// NETRA_SYSLOG_ADDR is set. Off by default. Best-effort; pull export
// still works if the collector is down. Leader-only callers must cancel
// on demote so two replicas never double-ship.
func startSyslog(ctx context.Context, log *slog.Logger, st *store.Store, wg *sync.WaitGroup) func() {
	addr := strings.TrimSpace(os.Getenv("NETRA_SYSLOG_ADDR"))
	if addr == "" || st == nil || wg == nil {
		return nil
	}
	fwd, err := siem.NewForwarder(siem.ForwardConfig{
		Network: env("NETRA_SYSLOG_NETWORK", "udp"),
		Addr:    addr,
		Format:  env("NETRA_SYSLOG_FORMAT", "syslog"),
		Timeout: envDuration("NETRA_SYSLOG_TIMEOUT", 3*time.Second),
	}, log)
	if err != nil {
		log.Error("syslog forwarder config", "error", err)
		os.Exit(1)
	}
	interval := envDuration("NETRA_SYSLOG_INTERVAL", 15*time.Second)
	sctx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("syslog forwarder started", "addr", addr, "interval", interval)
		fwd.Run(sctx, interval, func() []models.AuditEvent {
			return st.Audit(200)
		})
	}()
	return cancel
}

// sysctlExportDefaultTopN is the default row cap for the sysctl-audit
// Snowflake export. It is deliberately much larger than
// sysctlaudit.Build's own HTTP-handler default of 50 (see
// internal/api/server.go's ebpfSysctlAudit) — that default sizes an
// operator-facing HTTP page, and reusing it here would silently
// truncate findings per node, contradicting this export's contract of
// pushing the full current snapshot every tick.
const sysctlExportDefaultTopN = 100000

// startSnowflake starts the optional audit-event export sink when
// NETRA_SNOWFLAKE_ACCOUNT is set. Off by default. Same optional-feature
// shape as startSyslog: env-var gated, best-effort per flush, and
// leader-only in HA mode so two replicas never double-ship. Unlike
// startSyslog, this dials Snowflake and creates the target table once
// at startup, so a bad account/credential/warehouse config fails fast
// here — matching NETRA_API_KEY's fail-closed startup check — rather
// than being discovered later as a stream of failed-flush warnings.
//
// When NETRA_SNOWFLAKE_SYSCTL_ENABLED is also set, a second export loop
// runs alongside the audit loop, reusing the same Snowflake connection
// to push sysctl-audit findings into their own table. See
// docs/snowflake-export.md for why that table carries no watermark.
func startSnowflake(ctx context.Context, log *slog.Logger, st *store.Store, wg *sync.WaitGroup) func() {
	account := strings.TrimSpace(os.Getenv("NETRA_SNOWFLAKE_ACCOUNT"))
	if account == "" || st == nil || wg == nil {
		return nil
	}
	extraCols, err := snowflakesink.ParseExtraColumns(env("NETRA_SNOWFLAKE_EXTRA_COLUMNS", ""))
	if err != nil {
		log.Error("snowflake extra columns config", "error", err)
		os.Exit(1)
	}
	cfg := snowflakesink.Config{
		Account:        account,
		User:           env("NETRA_SNOWFLAKE_USER", ""),
		PrivateKeyPath: env("NETRA_SNOWFLAKE_PRIVATE_KEY_PATH", ""),
		Warehouse:      env("NETRA_SNOWFLAKE_WAREHOUSE", ""),
		Database:       env("NETRA_SNOWFLAKE_DATABASE", ""),
		Schema:         env("NETRA_SNOWFLAKE_SCHEMA", ""),
		Table:          env("NETRA_SNOWFLAKE_TABLE", "NETRA_AUDIT"),
		BatchSize:      envInt("NETRA_SNOWFLAKE_BATCH_SIZE", 50),
		ExtraColumns:   extraCols,
	}
	sink, err := snowflakesink.New(ctx, cfg, log)
	if err != nil {
		log.Error("snowflake sink config", "error", err)
		os.Exit(1)
	}
	interval := envDuration("NETRA_SNOWFLAKE_INTERVAL", 15*time.Second)
	sctx, cancel := context.WithCancel(ctx)

	// inner tracks only the export loops below, so sink.Close() (which
	// closes the *sql.DB both loops share) runs strictly after both have
	// fully returned regardless of goroutine scheduling order — without
	// this, one loop returning and closing the shared DB while the other
	// is still mid-flush would be a use-after-close race.
	var inner sync.WaitGroup

	inner.Add(1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer inner.Done()
		log.Info("snowflake sink started", "account", account, "table", cfg.Table, "interval", interval, "extraColumns", len(cfg.ExtraColumns))
		sink.Run(sctx, interval, func() []models.AuditEvent {
			return st.Audit(200)
		})
	}()

	if strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_SNOWFLAKE_SYSCTL_ENABLED")), "true") {
		sysctlCfg := snowflakesink.SysctlConfig{
			Table:     env("NETRA_SNOWFLAKE_SYSCTL_TABLE", "NETRA_SYSCTL_AUDIT"),
			BatchSize: envInt("NETRA_SNOWFLAKE_SYSCTL_BATCH_SIZE", 50),
		}
		sysctlSink, err := sink.NewSysctlSink(ctx, sysctlCfg)
		if err != nil {
			log.Error("snowflake sysctl sink config", "error", err)
			os.Exit(1)
		}
		sysctlInterval := envDuration("NETRA_SNOWFLAKE_SYSCTL_INTERVAL", 30*time.Second)
		staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
		topN := envInt("NETRA_SNOWFLAKE_SYSCTL_TOPN", sysctlExportDefaultTopN)

		inner.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer inner.Done()
			log.Info("snowflake sysctl sink started", "table", sysctlCfg.Table, "interval", sysctlInterval)
			sysctlSink.Run(sctx, sysctlInterval, func() models.SysctlAuditResponse {
				return sysctlaudit.Build(st.AgentStatuses(time.Now(), staleAfter), topN)
			})
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		inner.Wait()
		sink.Close()
	}()

	return cancel
}

// buildWorkloadObs reads NETRA_METRICS_WORKLOAD_* and NETRA_SLO_DEFINITIONS and
// returns the per-workload counter tracker / SLO observer, or nil when neither
// feature is on (the default). Malformed settings exit at startup: an SLO that
// is silently ignored is worse than a controller that refuses to start.
func buildWorkloadObs(log *slog.Logger) *workloadobs.Observer {
	cfg, err := workloadobs.ConfigFromEnv(os.Getenv)
	if err != nil {
		log.Error("workload observability config", "error", err)
		os.Exit(1)
	}
	if !cfg.Enabled() {
		return nil
	}
	o, err := workloadobs.NewObserver(cfg)
	if err != nil {
		log.Error("workload observability config", "error", err)
		os.Exit(1)
	}
	log.Info("workload observability enabled", "promSeries", cfg.PromSeries, "maxWorkloads", cfg.MaxWorkloads, "slos", len(cfg.SLOs), "interval", cfg.Interval)
	return o
}

// startWorkloadObs runs the observer loop, leader-only like the other push and
// detector loops. SLO burn/recovery transitions are written to the audit log,
// so they reach the SIEM, OTLP and Snowflake sinks without extra wiring.
func startWorkloadObs(ctx context.Context, log *slog.Logger, st *store.Store, o *workloadobs.Observer, wg *sync.WaitGroup) func() {
	if o == nil || st == nil || wg == nil {
		return nil
	}
	staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
	octx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.Run(octx,
			func() []models.AgentStatus { return st.AgentStatuses(time.Now(), staleAfter) },
			func(e models.AuditEvent) {
				if err := st.AddAudit(e); err != nil {
					log.Warn("slo audit event not recorded", "slo", e.Target, "error", err)
				}
			})
	}()
	return cancel
}

// startLoki starts the optional Loki push sink when NETRA_LOKI_URL is set. Off
// by default. Same optional-feature shape as startSyslog/startOTLP: env-var
// gated, best-effort per push, fail-fast on a bad config, and leader-only in
// HA mode so two replicas never double-ship. Audit events (including SLO burn
// and recovery) and block/deny events are pushed as JSON lines under a small
// bounded label set; see docs/loki-push.md.
func startLoki(ctx context.Context, log *slog.Logger, st *store.Store, wg *sync.WaitGroup) func() {
	url := strings.TrimSpace(os.Getenv("NETRA_LOKI_URL"))
	if url == "" || st == nil || wg == nil {
		return nil
	}
	fail := func(what string, err error) {
		log.Error("loki config", "setting", what, "error", err)
		os.Exit(1)
	}
	headers, err := pushfeed.ParseKeyValues(env("NETRA_LOKI_HEADERS", ""), "NETRA_LOKI_HEADERS")
	if err != nil {
		fail("headers", err)
	}
	labels, err := pushfeed.ParseKeyValues(env("NETRA_LOKI_LABELS", ""), "NETRA_LOKI_LABELS")
	if err != nil {
		fail("labels", err)
	}
	classes, err := lokipush.ParseClasses(env("NETRA_LOKI_CLASSES", ""))
	if err != nil {
		fail("classes", err)
	}
	pusher, err := lokipush.New(lokipush.Config{
		URL:      url,
		TenantID: strings.TrimSpace(os.Getenv("NETRA_LOKI_TENANT")),
		Username: os.Getenv("NETRA_LOKI_USERNAME"),
		Password: os.Getenv("NETRA_LOKI_PASSWORD"),
		Headers:  headers,
		Job:      strings.TrimSpace(os.Getenv("NETRA_LOKI_JOB")),
		Labels:   labels,
		Timeout:  envDuration("NETRA_LOKI_TIMEOUT", 5*time.Second),
		Classes:  classes,
	}, log)
	if err != nil {
		fail("exporter", err)
	}
	interval := envDuration("NETRA_LOKI_INTERVAL", 15*time.Second)
	staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
	src := lokipush.Sources{
		Audit: func() []models.AuditEvent { return st.Audit(200) },
		Blocks: func() map[string][]models.FastPathEvent {
			out := map[string][]models.FastPathEvent{}
			for _, a := range st.AgentStatuses(time.Now(), staleAfter) {
				out[a.Node] = append(out[a.Node], a.Events...)
			}
			return out
		},
	}
	lctx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("loki sink started", "url", url, "interval", interval, "tenant", os.Getenv("NETRA_LOKI_TENANT") != "")
		pusher.Run(lctx, interval, src)
	}()
	return cancel
}

// scrapeHeaders authenticates the exporter's in-process /metrics read when
// NETRA_METRICS_TOKEN gates that endpoint. Without it the push would start
// failing with 401 the moment an operator locks /metrics down.
func scrapeHeaders() http.Header {
	h := http.Header{}
	if tok := strings.TrimSpace(os.Getenv("NETRA_METRICS_TOKEN")); tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h
}

// buildOIDC reads NETRA_OIDC_* and returns the JWT verifier, or nil when
// NETRA_OIDC_ISSUER is unset (OIDC off — the default). Like the other
// security-relevant settings it fails fast: a half-configured or malformed
// setup exits at startup instead of silently running with only the static
// API key. The IdP itself is contacted lazily, so a briefly unreachable IdP
// does not stop the controller from starting.
func buildOIDC(log *slog.Logger) *oidcauth.Verifier {
	issuer := strings.TrimSpace(os.Getenv("NETRA_OIDC_ISSUER"))
	if issuer == "" {
		return nil
	}
	roleMap, err := oidcauth.ParseRoleMap(env("NETRA_OIDC_ROLE_MAP", ""))
	if err != nil {
		log.Error("oidc role map config", "error", err)
		os.Exit(1)
	}
	defaultRole, err := oidcauth.ParseRole(env("NETRA_OIDC_DEFAULT_ROLE", ""))
	if err != nil {
		log.Error("oidc default role config", "error", err)
		os.Exit(1)
	}
	v, err := oidcauth.New(oidcauth.Config{
		Issuer:            issuer,
		Audience:          env("NETRA_OIDC_AUDIENCE", ""),
		JWKSURL:           env("NETRA_OIDC_JWKS_URL", ""),
		RolesClaim:        env("NETRA_OIDC_ROLES_CLAIM", ""),
		RoleMap:           roleMap,
		DefaultRole:       defaultRole,
		IdentityClaim:     env("NETRA_OIDC_IDENTITY_CLAIM", ""),
		AllowInsecureHTTP: strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_OIDC_ALLOW_INSECURE_HTTP")), "true"),
		Logger:            log,
	})
	if err != nil {
		log.Error("oidc config", "error", err)
		os.Exit(1)
	}
	log.Info("oidc authentication enabled", "issuer", issuer, "audience", env("NETRA_OIDC_AUDIENCE", ""), "rolesClaim", env("NETRA_OIDC_ROLES_CLAIM", "roles"))
	return v
}

// startOTLP starts the optional OTLP/HTTP push exporter when
// NETRA_OTLP_ENDPOINT is set. Off by default. Same optional-feature shape as
// startSyslog: env-var gated, best-effort per push, fail-fast on a bad config,
// and leader-only in HA mode so two replicas never double-ship.
//
// Metrics are read in-process from the API's own /metrics handler, so the
// push and the scrape endpoint cannot drift apart. That internal request is
// counted by netra_http_requests_total like any other.
func startOTLP(ctx context.Context, log *slog.Logger, st *store.Store, apiHandler http.Handler, wg *sync.WaitGroup) func() {
	endpoint := strings.TrimSpace(os.Getenv("NETRA_OTLP_ENDPOINT"))
	if endpoint == "" || st == nil || apiHandler == nil || wg == nil {
		return nil
	}
	headers, err := otlppush.ParseHeaders(env("NETRA_OTLP_HEADERS", ""))
	if err != nil {
		log.Error("otlp headers config", "error", err)
		os.Exit(1)
	}
	signals, err := otlppush.ParseSignals(env("NETRA_OTLP_SIGNALS", ""))
	if err != nil {
		log.Error("otlp signals config", "error", err)
		os.Exit(1)
	}
	instance := strings.TrimSpace(os.Getenv("NETRA_POD_NAME"))
	if instance == "" {
		instance, _ = os.Hostname()
	}
	pusher, err := otlppush.New(otlppush.Config{
		Endpoint:   endpoint,
		Headers:    headers,
		Timeout:    envDuration("NETRA_OTLP_TIMEOUT", 5*time.Second),
		Signals:    signals,
		InstanceID: instance,
		Version:    version,
	}, log)
	if err != nil {
		log.Error("otlp exporter config", "error", err)
		os.Exit(1)
	}
	interval := envDuration("NETRA_OTLP_INTERVAL", 30*time.Second)
	staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
	src := otlppush.Sources{
		Metrics: otlppush.ScrapeHandler(apiHandler, "/metrics", scrapeHeaders()),
		Audit:   func() []models.AuditEvent { return st.Audit(200) },
		Blocks: func() map[string][]models.FastPathEvent {
			out := map[string][]models.FastPathEvent{}
			for _, a := range st.AgentStatuses(time.Now(), staleAfter) {
				out[a.Node] = append(out[a.Node], a.Events...)
			}
			return out
		},
	}
	octx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("otlp exporter started", "endpoint", endpoint, "interval", interval, "signals", signals)
		pusher.Run(octx, interval, src)
	}()
	return cancel
}

// buildGitOps reads NETRA_GITOPS_DIR/NETRA_GITOPS_AUTO_APPLY/NETRA_GITOPS_INTERVAL.
// An empty NETRA_GITOPS_DIR means GitOps is off — the supported default,
// matching every other optional feature in this codebase.
func buildGitOps() (gitops.Config, bool) {
	dir := strings.TrimSpace(os.Getenv("NETRA_GITOPS_DIR"))
	if dir == "" {
		return gitops.Config{}, false
	}
	return gitops.Config{
		Dir:       dir,
		AutoApply: strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_GITOPS_AUTO_APPLY")), "true"),
		Interval:  envDuration("NETRA_GITOPS_INTERVAL", 60*time.Second),
	}, true
}

// buildAlerting constructs the notify dispatcher and alert-poller config
// from env vars. Prefer NETRA_ALERT_CHANNELS; fall back to legacy
// NETRA_ALERT_WEBHOOKS. Returns a nil dispatcher (alerting fully disabled)
// when both are unset, matching the off-by-default convention used for
// every other optional feature in this codebase.
func buildAlerting(log *slog.Logger) (*notify.Dispatcher, alert.Config) {
	cfg := alert.Config{
		Interval:             envDuration("NETRA_ALERT_POLL_INTERVAL", 30*time.Second),
		Cooldown:             envDuration("NETRA_ALERT_COOLDOWN", 5*time.Minute),
		StaleAfter:           envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second),
		TopN:                 envInt("NETRA_ALERT_TOPN", 0),
		DropSpikeWindow:      envInt("NETRA_DROP_SPIKE_WINDOW", 0),
		DropSpikeMultiplier:  envFloat("NETRA_DROP_SPIKE_MULTIPLIER", 0),
		DropSpikeMinAbsolute: envUint64("NETRA_DROP_SPIKE_MIN_ABSOLUTE", 0),
	}
	channelsRaw := strings.TrimSpace(os.Getenv("NETRA_ALERT_CHANNELS"))
	webhooksRaw := strings.TrimSpace(os.Getenv("NETRA_ALERT_WEBHOOKS"))
	if channelsRaw == "" && webhooksRaw == "" {
		return nil, cfg
	}
	var (
		chs []notify.Channel
		err error
	)
	if channelsRaw != "" {
		chs, err = notify.ParseChannels(channelsRaw)
		if err != nil {
			log.Error("alert channels config", "error", err)
			os.Exit(1)
		}
	} else {
		chs, err = notify.ParseLegacyWebhooks(webhooksRaw)
		if err != nil {
			log.Error("alert webhook config", "error", err)
			os.Exit(1)
		}
	}
	d := notify.NewDispatcher(envInt("NETRA_ALERT_QUEUE_SIZE", 256))
	for _, ch := range chs {
		d.Add(ch)
	}
	return d, cfg
}

func autoCaptureEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_AUTO_CAPTURE")), "true")
}

func shouldRunAlertPoller(dispatcher *notify.Dispatcher) bool {
	return dispatcher != nil || autoCaptureEnabled()
}

func buildArtifactStore(log *slog.Logger) *capture.ArtifactStore {
	if !autoCaptureEnabled() {
		return nil
	}
	dir := strings.TrimSpace(os.Getenv("NETRA_AUTO_CAPTURE_DIR"))
	if dir == "" {
		dir = capture.DefaultArtifactDir
	}
	maxArt := envInt("NETRA_AUTO_CAPTURE_MAX_ARTIFACTS", capture.DefaultMaxArtifacts)
	maxTotal := int64(envInt("NETRA_AUTO_CAPTURE_MAX_TOTAL_MB", int(capture.DefaultMaxTotalBytes/(1<<20)))) << 20
	maxSession := int64(envInt("NETRA_AUTO_CAPTURE_MAX_SESSION_MB", int(capture.DefaultMaxSessionBytes/(1<<20)))) << 20
	store, err := capture.NewArtifactStore(dir, maxArt, maxTotal, maxSession)
	if err != nil {
		log.Error("auto-capture artifact store", "error", err)
		os.Exit(1)
	}
	log.Info("auto-capture artifact store ready", "dir", dir)
	return store
}

func newAlertPoller(log *slog.Logger, st *store.Store, dispatcher *notify.Dispatcher, alertCfg alert.Config, listPods func(ctx context.Context, ns string) ([]models.PodInfo, error), artifacts *capture.ArtifactStore) *alert.Poller {
	publish := func(ev notify.Event) bool {
		if dispatcher == nil {
			return true
		}
		return dispatcher.Publish(ev)
	}
	p := alert.New(log, st, publish, alertCfg, listPods)
	if !autoCaptureEnabled() {
		return p
	}
	cfg := alert.AutoConfig{
		Enabled:       true,
		Duration:      envDuration("NETRA_AUTO_CAPTURE_DURATION", 60*time.Second),
		Cooldown:      envDuration("NETRA_AUTO_CAPTURE_COOLDOWN", 10*time.Minute),
		Protocol:      env("NETRA_AUTO_CAPTURE_PROTOCOL", "tcp"),
		Backend:       env("NETRA_AUTO_CAPTURE_BACKEND", models.CaptureBackendEBPF),
		MaxPPS:        envUint32("NETRA_AUTO_CAPTURE_MAX_PPS", 1000),
		MaxConcurrent: envInt("NETRA_AUTO_CAPTURE_MAX_CONCURRENT", 5),
	}
	auto := alert.NewAutoCapture(log, cfg,
		func(spec models.CaptureSpec) models.CaptureSpec {
			return st.SetCapture(spec, spec.Requestor)
		},
		func(node string) *models.CaptureSpec { return st.Capture(node) },
		func() int { return len(st.Captures()) },
		publish,
	)
	if artifacts != nil {
		auto.WithStage(artifacts.StageContext)
	}
	return p.WithAutoCapture(auto)
}

// buildDNSDetect reads NETRA_DNSDETECT_* env vars and constructs a
// dnsdetect.Detector when enabled. Off by default via a plain feature
// flag — matching gitops/chatops's "enabled: false" shape rather than a
// "presence of one required value" gate, since there's no single natural
// required config value here (every dnsdetect.Config field already has a
// sane default).
func buildDNSDetect() (*dnsdetect.Detector, time.Duration, bool) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_DNSDETECT_ENABLED")), "true") {
		return nil, 0, false
	}
	cfg := dnsdetect.DefaultConfig()
	if v := envInt("NETRA_DNSDETECT_MAX_UNIQUE_SUBDOMAINS", 0); v > 0 {
		cfg.MaxUniqueSubdomains = v
	}
	if v := envFloat("NETRA_DNSDETECT_NXDOMAIN_RATIO", 0); v > 0 {
		cfg.NXDomainRatio = v
	}
	if v := envFloat("NETRA_DNSDETECT_SERVFAIL_RATIO", 0); v > 0 {
		cfg.ServfailRatio = v
	}
	if v := envInt("NETRA_DNSDETECT_MAX_DOMAINS", 0); v > 0 {
		cfg.MaxDomains = v
	}
	if v := envDuration("NETRA_DNSDETECT_FINDINGS_TTL", 0); v > 0 {
		cfg.FindingsTTL = v
	}
	interval := envDuration("NETRA_DNSDETECT_INTERVAL", 30*time.Second)
	return dnsdetect.New(cfg), interval, true
}

// buildScanDetect is scandetect's analog of buildDNSDetect above.
func buildScanDetect() (*scandetect.Detector, time.Duration, bool) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_SCANDETECT_ENABLED")), "true") {
		return nil, 0, false
	}
	cfg := scandetect.DefaultConfig()
	if v := envDuration("NETRA_SCANDETECT_WINDOW", 0); v > 0 {
		cfg.Window = v
	}
	if v := envInt("NETRA_SCANDETECT_MAX_DEST_IPS", 0); v > 0 {
		cfg.MaxDestIPs = v
	}
	if v := envInt("NETRA_SCANDETECT_MAX_DEST_PORTS", 0); v > 0 {
		cfg.MaxDestPorts = v
	}
	if v := envUint64("NETRA_SCANDETECT_MIN_ATTEMPTS", 0); v > 0 {
		cfg.MinAttempts = v
	}
	interval := envDuration("NETRA_SCANDETECT_INTERVAL", 30*time.Second)
	return scandetect.New(cfg), interval, true
}

// buildAutoMitigate wires optional lease-bounded volumetric mitigation.
func buildAutoMitigate(log *slog.Logger, st *store.Store, scan *scandetect.Detector) (*automitigate.Engine, bool) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_AUTOMITIGATE_ENABLED")), "true") {
		return nil, false
	}
	cfg := automitigate.DefaultConfig()
	cfg.Enabled = true
	if v := envDuration("NETRA_AUTOMITIGATE_INTERVAL", 0); v > 0 {
		cfg.Interval = v
	}
	if v := envUint32("NETRA_AUTOMITIGATE_CONN_RATE", 0); v > 0 {
		cfg.ConnRatePerSecond = v
	}
	if v := envUint64("NETRA_AUTOMITIGATE_UDP_DELTA", 0); v > 0 {
		cfg.UDPPacketDelta = v
	}
	if v := envUint32("NETRA_AUTOMITIGATE_SHIELD_UDP_PPS", 0); v > 0 {
		cfg.ShieldUDPPPS = v
	}
	if v := envUint32("NETRA_AUTOMITIGATE_SHIELD_SYN_PPS", 0); v > 0 {
		cfg.ShieldSynPPS = v
	}
	return automitigate.New(log, st, scan, cfg), true
}

func envUint32(key string, def uint32) uint32 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return def
	}
	return uint32(n)
}

func runHA(ctx context.Context, log *slog.Logger, k *kube.Client, h *hubble.Client, stateFile string, dispatcher *notify.Dispatcher, alertCfg alert.Config, artifacts *capture.ArtifactStore, gitopsCfg gitops.Config, gitopsEnabled bool) {
	identity := strings.TrimSpace(os.Getenv("NETRA_POD_NAME"))
	if identity == "" {
		identity, _ = os.Hostname()
	}
	if identity == "" {
		identity = "netra-unknown"
	}
	namespace := env("NETRA_NAMESPACE", "netra")
	leaseName := env("NETRA_HA_LEASE_NAME", "netra-controller")
	leaseDuration := envDuration("NETRA_HA_LEASE_DURATION", 15*time.Second)
	renewDeadline := envDuration("NETRA_HA_RENEW_DEADLINE", 10*time.Second)
	retryPeriod := envDuration("NETRA_HA_RETRY_PERIOD", 2*time.Second)
	if retryPeriod <= 0 || renewDeadline <= retryPeriod || leaseDuration <= renewDeadline {
		log.Error("invalid HA timing", "leaseDuration", leaseDuration, "renewDeadline", renewDeadline, "retryPeriod", retryPeriod)
		os.Exit(1)
	}

	gate := ha.NewGate(identity, version)
	// Tracked (not fire-and-forget) so runHA can wait for electionLoop —
	// and therefore any alert poller it started on this replica's last
	// leadership stint — to fully stop before the caller stops the shared
	// dispatcher, so in-flight alert deliveries aren't cut off mid-shutdown.
	var electionWG sync.WaitGroup
	electionWG.Add(1)
	go func() {
		defer electionWG.Done()
		electionLoop(ctx, log, k, h, gate, stateFile, namespace, leaseName, identity, leaseDuration, renewDeadline, retryPeriod, dispatcher, alertCfg, artifacts, gitopsCfg, gitopsEnabled)
	}()
	runHTTP(ctx, log, gate, true, true)
	electionWG.Wait()
}

func electionLoop(
	ctx context.Context,
	log *slog.Logger,
	k *kube.Client,
	h *hubble.Client,
	gate *ha.Gate,
	stateFile, namespace, leaseName, identity string,
	leaseDuration, renewDeadline, retryPeriod time.Duration,
	dispatcher *notify.Dispatcher,
	alertCfg alert.Config,
	artifacts *capture.ArtifactStore,
	gitopsCfg gitops.Config,
	gitopsEnabled bool,
) {
	var st *store.Store
	var lastRenew time.Time
	// pollerCancel/pollerWG (and gitopsCancel/gitopsWG, identically) track
	// the alert poller (and GitOps reconciler) started on this replica's
	// current leadership stint, if any. Tied 1:1 to the store's own
	// open/close lifecycle rather than to ha.Gate, which exposes no "give
	// me the current store" query.
	var pollerCancel func()
	var pollerWG sync.WaitGroup
	var gitopsCancel func()
	var gitopsWG sync.WaitGroup
	var syslogCancel func()
	var syslogWG sync.WaitGroup
	var snowflakeCancel func()
	var snowflakeWG sync.WaitGroup
	var otlpCancel func()
	var otlpWG sync.WaitGroup
	var wobsCancel func()
	var wobsWG sync.WaitGroup
	var lokiCancel func()
	var lokiWG sync.WaitGroup
	var dnsDetectCancel func()
	var dnsDetectWG sync.WaitGroup
	var scanDetectCancel func()
	var scanDetectWG sync.WaitGroup
	var autoMitigateCancel func()
	var autoMitigateWG sync.WaitGroup
	var metricsCancel func()
	var metricsWG sync.WaitGroup

	demote := func(reason string) {
		if !gate.IsLeader() {
			return
		}
		gate.Demote()
		if metricsCancel != nil {
			metricsCancel()
			metricsWG.Wait()
			metricsCancel = nil
		}
		if pollerCancel != nil {
			pollerCancel()
			pollerWG.Wait()
			pollerCancel = nil
		}
		if gitopsCancel != nil {
			gitopsCancel()
			gitopsWG.Wait()
			gitopsCancel = nil
		}
		if syslogCancel != nil {
			syslogCancel()
			syslogWG.Wait()
			syslogCancel = nil
		}
		if snowflakeCancel != nil {
			snowflakeCancel()
			snowflakeWG.Wait()
			snowflakeCancel = nil
		}
		if otlpCancel != nil {
			otlpCancel()
			otlpWG.Wait()
			otlpCancel = nil
		}
		if wobsCancel != nil {
			wobsCancel()
			wobsWG.Wait()
			wobsCancel = nil
		}
		if lokiCancel != nil {
			lokiCancel()
			lokiWG.Wait()
			lokiCancel = nil
		}
		if dnsDetectCancel != nil {
			dnsDetectCancel()
			dnsDetectWG.Wait()
			dnsDetectCancel = nil
		}
		if scanDetectCancel != nil {
			scanDetectCancel()
			scanDetectWG.Wait()
			scanDetectCancel = nil
		}
		if autoMitigateCancel != nil {
			autoMitigateCancel()
			autoMitigateWG.Wait()
			autoMitigateCancel = nil
		}
		if st != nil {
			if err := st.Close(); err != nil {
				log.Error("close leader state", "error", err)
			}
			st = nil
		}
		log.Warn("controller demoted", "identity", identity, "reason", reason)
	}
	defer func() {
		demote("shutdown")
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := k.ReleaseLease(c, namespace, leaseName, identity); err != nil {
			log.Warn("release leader lease", "error", err)
		}
	}()

	attempt := func() {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		acquired, err := k.TryAcquireOrRenewLease(c, namespace, leaseName, identity, leaseDuration)
		cancel()
		if err != nil {
			log.Warn("leader lease renewal failed", "error", err)
			if gate.IsLeader() && !lastRenew.IsZero() && time.Since(lastRenew) >= renewDeadline {
				demote("renew deadline exceeded")
			}
			return
		}
		if !acquired {
			demote("lease held by another replica")
			return
		}
		lastRenew = time.Now()
		if gate.IsLeader() {
			return
		}

		opened, err := store.Open(stateFile)
		if err != nil {
			log.Warn("lease acquired but shared state lock unavailable", "error", err)
			c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = k.ReleaseLease(c, namespace, leaseName, identity)
			cancel()
			return
		}
		st = opened
		var gr *gitops.Reconciler
		if gitopsEnabled {
			gr = gitops.New(log, k, st, gitopsCfg)
		}
		dnsDet, dnsInterval, dnsEnabled := buildDNSDetect()
		scanDet, scanInterval, scanEnabled := buildScanDetect()
		autoEng, autoEnabled := buildAutoMitigate(log, st, scanDet)
		wobs := buildWorkloadObs(log)
		metrics := buildMetrics(log, stateFile, dispatcher)
		apiHandler := api.New(log, k, h, st).WithOIDC(buildOIDC(log)).WithWorkloadObs(wobs).WithGitOps(gr).WithDNSDetect(dnsDet).WithScanDetect(scanDet).WithAutoMitigate(autoEng).WithArtifacts(artifacts).WithMetrics(metrics.hubOrNil()).WithMetricAlerts(metrics.alertsOrNil()).WithMetricExporters(metrics.exporterStatus).Handler()
		if stop := metrics.start(ctx, &metricsWG); stop != nil {
			metricsCancel = stop
		}
		gate.Promote(apiHandler)
		if shouldRunAlertPoller(dispatcher) {
			pctx, cancel := context.WithCancel(ctx)
			pollerCancel = cancel
			pollerWG.Add(1)
			go func() {
				defer pollerWG.Done()
				newAlertPoller(log, st, dispatcher, alertCfg, k.ListPods, artifacts).Run(pctx)
			}()
		}
		if gr != nil {
			gctx, gcancel := context.WithCancel(ctx)
			gitopsCancel = gcancel
			gitopsWG.Add(1)
			go func() {
				defer gitopsWG.Done()
				gr.Run(gctx)
			}()
		}
		if stop := startSyslog(ctx, log, st, &syslogWG); stop != nil {
			syslogCancel = stop
		}
		if stop := startSnowflake(ctx, log, st, &snowflakeWG); stop != nil {
			snowflakeCancel = stop
		}
		if stop := startOTLP(ctx, log, st, apiHandler, &otlpWG); stop != nil {
			otlpCancel = stop
		}
		if stop := startWorkloadObs(ctx, log, st, wobs, &wobsWG); stop != nil {
			wobsCancel = stop
		}
		if stop := startLoki(ctx, log, st, &lokiWG); stop != nil {
			lokiCancel = stop
		}
		staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
		// leaderSt pins this stint's specific *store.Store: st is an outer
		// variable electionLoop reassigns (to nil on demote, to a new store
		// on the next promotion), so a closure capturing st directly would
		// read whatever the *next* stint left there instead of this one's —
		// exactly the failure alert.New(log, st, ...) avoids by taking st as
		// a plain argument, copied once, at call time.
		leaderSt := st
		if dnsEnabled {
			dctx, dcancel := context.WithCancel(ctx)
			dnsDetectCancel = dcancel
			dnsDetectWG.Add(1)
			go func() {
				defer dnsDetectWG.Done()
				dnsDet.Run(dctx, dnsInterval, func() []models.AgentStatus { return leaderSt.AgentStatuses(time.Now(), staleAfter) })
			}()
		}
		if scanEnabled {
			sctx, scancel := context.WithCancel(ctx)
			scanDetectCancel = scancel
			scanDetectWG.Add(1)
			go func() {
				defer scanDetectWG.Done()
				scanDet.Run(sctx, scanInterval, func() []models.AgentStatus { return leaderSt.AgentStatuses(time.Now(), staleAfter) })
			}()
		}
		if autoEnabled {
			actx, acancel := context.WithCancel(ctx)
			autoMitigateCancel = acancel
			autoMitigateWG.Add(1)
			go func() {
				defer autoMitigateWG.Done()
				autoEng.Run(actx, func() []models.AgentStatus { return leaderSt.AgentStatuses(time.Now(), staleAfter) })
			}()
		}
		log.Info("controller promoted", "identity", identity, "lease", namespace+"/"+leaseName, "stateFile", stateFile)
	}

	attempt()
	ticker := time.NewTicker(retryPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			attempt()
		}
	}
}

// tlsConfigured is whether the listener will serve HTTPS.
func tlsConfigured() bool {
	return strings.TrimSpace(os.Getenv("NETRA_TLS_CERT")) != "" && strings.TrimSpace(os.Getenv("NETRA_TLS_KEY")) != ""
}

func runHTTP(ctx context.Context, log *slog.Logger, handler http.Handler, persistent, haMode bool) {
	s := &http.Server{
		Addr:              env("NETRA_LISTEN", ":30870"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.Shutdown(c)
	}()
	certFile := strings.TrimSpace(os.Getenv("NETRA_TLS_CERT"))
	keyFile := strings.TrimSpace(os.Getenv("NETRA_TLS_KEY"))
	tlsOn := certFile != "" && keyFile != ""
	mode, tlsCfg, err := mtls.FromEnv(tlsOn)
	if err != nil { // main already refused this; a second check costs nothing
		log.Error("server", "error", err)
		return
	}
	s.TLSConfig = tlsCfg
	log.Info("netrad starting", "addr", s.Addr, "version", version, "persistentState", persistent, "ha", haMode, "tls", tlsOn, "agentMTLS", string(mode))
	if tlsOn {
		err = s.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = s.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "error", err)
	}
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envDuration(k string, d time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			return parsed
		}
	}
	return d
}

func envInt(k string, d int) int {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			return parsed
		}
	}
	return d
}

func envFloat(k string, d float64) float64 {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			return parsed
		}
	}
	return d
}

func envUint64(k string, d uint64) uint64 {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			return parsed
		}
	}
	return d
}
