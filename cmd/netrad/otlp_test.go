// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/alert"
	"github.com/zyvorai/netra/internal/api"
	"github.com/zyvorai/netra/internal/gitops"
	"github.com/zyvorai/netra/internal/ha"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

type otlpRecorder struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string][][]byte
	hdr  http.Header
}

func newOTLPRecorder(t *testing.T) *otlpRecorder {
	t.Helper()
	r := &otlpRecorder{hits: map[string][][]byte{}}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.hits[req.URL.Path] = append(r.hits[req.URL.Path], b)
		r.hdr = req.Header.Clone()
		r.mu.Unlock()
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *otlpRecorder) count(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.hits[path])
}

func (r *otlpRecorder) first(path string) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hits[path]) == 0 {
		return nil
	}
	return r.hits[path][0]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStartOTLPIsOffUnlessConfigured(t *testing.T) {
	t.Setenv("NETRA_OTLP_ENDPOINT", "")
	var wg sync.WaitGroup
	if stop := startOTLP(context.Background(), slog.Default(), store.New(), http.NotFoundHandler(), &wg); stop != nil {
		t.Fatal("startOTLP must be a no-op without NETRA_OTLP_ENDPOINT")
	}
}

// Drives the real API handler's /metrics through the exporter, so this fails
// if the exposition netrad actually serves stops converting cleanly.
func TestStartOTLPPushesRealMetricsAndAuditThenStops(t *testing.T) {
	rec := newOTLPRecorder(t)
	t.Setenv("NETRA_OTLP_ENDPOINT", rec.URL)
	t.Setenv("NETRA_OTLP_HEADERS", "Authorization=Bearer tok")
	t.Setenv("NETRA_OTLP_INTERVAL", "20ms")
	t.Setenv("NETRA_POD_NAME", "netra-0")

	st := store.New()
	if err := st.AddAudit(models.AuditEvent{At: time.Now().UTC(), Actor: "op", Action: "policy.apply", Target: "p1"}); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	handler := api.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st).Handler()

	var wg sync.WaitGroup
	stop := startOTLP(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), st, handler, &wg)
	if stop == nil {
		t.Fatal("startOTLP returned nil with an endpoint configured")
	}

	waitFor(t, "a metrics and a logs push", func() bool { return rec.count("/v1/metrics") >= 1 && rec.count("/v1/logs") >= 1 })

	body := rec.first("/v1/metrics")
	var doc struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []struct {
					Key   string `json:"key"`
					Value struct {
						S string `json:"stringValue"`
					} `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
			ScopeMetrics []struct {
				Metrics []struct {
					Name string          `json:"name"`
					Sum  json.RawMessage `json:"sum"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("metrics body is not JSON: %v", err)
	}
	names := map[string]bool{}
	sums := map[string]bool{}
	for _, m := range doc.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		names[m.Name] = true
		if len(m.Sum) > 0 {
			sums[m.Name] = true
		}
	}
	if !names["netra_agents_total"] {
		t.Fatalf("real /metrics gauge missing from push; got %d metrics", len(names))
	}
	if !sums["netra_http_requests_total"] {
		t.Fatal("a Prometheus counter should arrive as an OTLP sum")
	}
	instance := ""
	for _, a := range doc.ResourceMetrics[0].Resource.Attributes {
		if a.Key == "service.instance.id" {
			instance = a.Value.S
		}
	}
	if instance != "netra-0" {
		t.Fatalf("service.instance.id = %q, want netra-0", instance)
	}
	rec.mu.Lock()
	auth := rec.hdr.Get("Authorization")
	rec.mu.Unlock()
	if auth != "Bearer tok" {
		t.Fatalf("NETRA_OTLP_HEADERS not applied, Authorization = %q", auth)
	}
	if !strings.Contains(string(rec.first("/v1/logs")), "policy.apply") {
		t.Fatalf("audit event missing from logs push: %s", rec.first("/v1/logs"))
	}

	stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("exporter goroutine did not exit after cancel")
	}
	before := rec.count("/v1/metrics")
	time.Sleep(100 * time.Millisecond)
	if after := rec.count("/v1/metrics"); after != before {
		t.Fatalf("pushes continued after cancel: %d -> %d", before, after)
	}
}

// The exporter is leader-only: it must start on promotion and be fully torn
// down on demote/shutdown. Two replicas share one lease and a forced
// handoff, under -race. After both exit, nothing may still be pushing —
// a leaked exporter would keep shipping from a replica that lost the lease.
func TestElectionLoopStopsOTLPExporterOnDemote(t *testing.T) {
	rec := newOTLPRecorder(t)
	t.Setenv("NETRA_OTLP_ENDPOINT", rec.URL)
	t.Setenv("NETRA_OTLP_INTERVAL", "15ms")

	fakeLease := &fakeLeaseServer{}
	ts := httptest.NewServer(fakeLease)
	defer ts.Close()

	stateFile := filepath.Join(t.TempDir(), "state.json")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	run := func(ctx context.Context, wg *sync.WaitGroup, identity string) {
		defer wg.Done()
		k := kube.NewForTesting(ts.URL, ts.Client())
		gate := ha.NewGate(identity, "test")
		electionLoop(ctx, log, k, nil, gate, stateFile, "netra", "controller", identity,
			200*time.Millisecond, 140*time.Millisecond, 30*time.Millisecond,
			nil, alert.Config{}, nil, gitops.Config{}, false)
	}

	parent, cancelAll := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancelAll()
	var wg sync.WaitGroup
	ctxA, cancelA := context.WithCancel(parent)
	wg.Add(1)
	go run(ctxA, &wg, "replica-a")
	time.Sleep(70 * time.Millisecond)
	ctxB, cancelB := context.WithCancel(parent)
	defer cancelB()
	wg.Add(1)
	go run(ctxB, &wg, "replica-b")
	time.Sleep(200 * time.Millisecond)
	cancelA() // forced handoff

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("electionLoop did not return: the OTLP exporter likely blocked demote")
	}

	if rec.count("/v1/metrics") == 0 {
		t.Fatal("no leader ever pushed metrics")
	}
	before := rec.count("/v1/metrics")
	time.Sleep(120 * time.Millisecond)
	if after := rec.count("/v1/metrics"); after != before {
		t.Fatalf("exporter kept pushing after both replicas exited: %d -> %d", before, after)
	}
}

// Locking /metrics with NETRA_METRICS_TOKEN must not break the OTLP push,
// which reads that same endpoint in-process.
func TestStartOTLPStillPushesWhenMetricsAreTokenGated(t *testing.T) {
	rec := newOTLPRecorder(t)
	t.Setenv("NETRA_OTLP_ENDPOINT", rec.URL)
	t.Setenv("NETRA_OTLP_INTERVAL", "20ms")
	t.Setenv("NETRA_OTLP_SIGNALS", "metrics")
	t.Setenv("NETRA_API_KEY", "k")
	t.Setenv("NETRA_METRICS_TOKEN", "scrape-secret")

	st := store.New()
	handler := api.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, st).Handler()

	// Sanity: the gate really is closed to an unauthenticated reader.
	probe := httptest.NewRecorder()
	handler.ServeHTTP(probe, httptest.NewRequest("GET", "/metrics", nil))
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics without a token = %d, want 401 (gate not active)", probe.Code)
	}

	var wg sync.WaitGroup
	stop := startOTLP(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), st, handler, &wg)
	if stop == nil {
		t.Fatal("startOTLP returned nil")
	}
	defer func() { stop(); wg.Wait() }()
	waitFor(t, "a metrics push through the token gate", func() bool { return rec.count("/v1/metrics") >= 1 })
	if !strings.Contains(string(rec.first("/v1/metrics")), "netra_agents_total") {
		t.Fatalf("pushed body has no netra metrics: %s", rec.first("/v1/metrics"))
	}
}

// buildOIDC exits the process on bad config so a half-configured login never
// runs silently with only the static key. os.Exit cannot be observed
// in-process, so each case re-executes the test binary.
func TestBuildOIDCFailsFastOnBadConfig(t *testing.T) {
	if os.Getenv("NETRA_TEST_BUILD_OIDC") == "1" {
		buildOIDC(slog.New(slog.NewTextHandler(io.Discard, nil)))
		os.Exit(0) // reached only if config was accepted
	}
	base := []string{"NETRA_OIDC_ISSUER=https://idp.example", "NETRA_OIDC_AUDIENCE=netra"}
	cases := []struct {
		name     string
		env      []string
		wantExit int
	}{
		{"valid", base, 0},
		{"off when no issuer", []string{"NETRA_OIDC_ISSUER="}, 0},
		{"missing audience", []string{"NETRA_OIDC_ISSUER=https://idp.example"}, 1},
		{"http issuer without the dev flag", []string{"NETRA_OIDC_ISSUER=http://idp.example", "NETRA_OIDC_AUDIENCE=netra"}, 1},
		{"http issuer with the dev flag", []string{"NETRA_OIDC_ISSUER=http://idp.example", "NETRA_OIDC_AUDIENCE=netra", "NETRA_OIDC_ALLOW_INSECURE_HTTP=true"}, 0},
		{"malformed role map", append([]string{"NETRA_OIDC_ROLE_MAP=admins"}, base...), 1},
		{"role map naming an unknown role", append([]string{"NETRA_OIDC_ROLE_MAP=admins=root"}, base...), 1},
		{"unknown default role", append([]string{"NETRA_OIDC_DEFAULT_ROLE=superuser"}, base...), 1},
		{"valid role map and default role", append([]string{"NETRA_OIDC_ROLE_MAP=a=admin,b=viewer", "NETRA_OIDC_DEFAULT_ROLE=viewer"}, base...), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBuildOIDCFailsFastOnBadConfig$")
			cmd.Env = append(cleanOIDCEnv(), append(tc.env, "NETRA_TEST_BUILD_OIDC=1")...)
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("running child: %v", err)
			}
			if code != tc.wantExit {
				t.Fatalf("exit code = %d, want %d", code, tc.wantExit)
			}
		})
	}
}

func cleanOIDCEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "NETRA_OIDC_") && !strings.HasPrefix(kv, "NETRA_TEST_BUILD_OIDC") {
			out = append(out, kv)
		}
	}
	return out
}
