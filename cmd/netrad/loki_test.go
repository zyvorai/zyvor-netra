// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func TestStartLokiIsOffUnlessConfigured(t *testing.T) {
	t.Setenv("NETRA_LOKI_URL", "")
	var wg sync.WaitGroup
	if stop := startLoki(context.Background(), slog.Default(), store.New(), &wg); stop != nil {
		t.Fatal("startLoki must be a no-op without NETRA_LOKI_URL")
	}
}

// Drives the real startLoki against a receiver: audit events and an agent's
// block events go out, with the tenant, auth and static labels from the env.
func TestStartLokiPushesAuditAndBlockEventsThenStops(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var hdr http.Header
	var user string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		hdr = r.Header.Clone()
		user, _, _ = r.BasicAuth()
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("NETRA_LOKI_URL", srv.URL)
	t.Setenv("NETRA_LOKI_INTERVAL", "20ms")
	t.Setenv("NETRA_LOKI_TENANT", "acme")
	t.Setenv("NETRA_LOKI_USERNAME", "grafana")
	t.Setenv("NETRA_LOKI_PASSWORD", "pw")
	t.Setenv("NETRA_LOKI_LABELS", "cluster=prod")

	st := store.New()
	now := time.Now().UTC()
	if err := st.AddAudit(models.AuditEvent{At: now, Actor: "op", Action: "policy.apply", Target: "p1"}); err != nil {
		t.Fatal(err)
	}
	st.Report(models.AgentReport{Node: "n1", ObservedAt: now, Events: []models.FastPathEvent{
		{ObservedAt: now, Action: "blocked", DestinationIP: "9.9.9.9", Protocol: "tcp", Reason: "denylist"},
	}})

	var wg sync.WaitGroup
	stop := startLoki(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), st, &wg)
	if stop == nil {
		t.Fatal("startLoki returned nil with a URL configured")
	}
	waitFor(t, "audit and block pushes", func() bool {
		mu.Lock()
		defer mu.Unlock()
		joined := strings.Join(bodies, "")
		return strings.Contains(joined, `\"policy.apply\"`) || strings.Contains(joined, "policy.apply")
	})
	waitFor(t, "the block event", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(strings.Join(bodies, ""), "9.9.9.9")
	})

	mu.Lock()
	all := strings.Join(bodies, "")
	if hdr.Get("X-Scope-OrgID") != "acme" || user != "grafana" {
		t.Errorf("tenant/auth not applied: tenant=%q user=%q", hdr.Get("X-Scope-OrgID"), user)
	}
	first := bodies[0]
	mu.Unlock()
	var p struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
		} `json:"streams"`
	}
	if err := json.Unmarshal([]byte(first), &p); err != nil || len(p.Streams) == 0 {
		t.Fatalf("first push is not a Loki payload: %v %.120s", err, first)
	}
	if p.Streams[0].Stream["cluster"] != "prod" || p.Streams[0].Stream["job"] != "netra" {
		t.Errorf("labels = %v", p.Streams[0].Stream)
	}
	if !strings.Contains(all, `"class":"block"`) && !strings.Contains(strings.ReplaceAll(all, `\"`, `"`), `"class":"block"`) {
		t.Errorf("no block-class line pushed: %.300s", all)
	}

	stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the loki sink did not exit after cancel")
	}
}

// startLoki exits on a malformed setting so a half-configured sink never runs
// silently. os.Exit cannot be observed in-process: re-execute the test binary.
func TestStartLokiFailsFastOnBadConfig(t *testing.T) {
	if os.Getenv("NETRA_TEST_START_LOKI") == "1" {
		var wg sync.WaitGroup
		if stop := startLoki(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store.New(), &wg); stop != nil {
			stop()
		}
		os.Exit(0)
	}
	cases := []struct {
		name string
		env  []string
		want int
	}{
		{"off when no url", nil, 0},
		{"valid", []string{"NETRA_LOKI_URL=http://loki:3100"}, 0},
		{"valid with everything", []string{"NETRA_LOKI_URL=https://loki.example", "NETRA_LOKI_TENANT=t", "NETRA_LOKI_LABELS=cluster=a,env=b", "NETRA_LOKI_CLASSES=audit"}, 0},
		{"non-http url", []string{"NETRA_LOKI_URL=ftp://loki"}, 1},
		{"credentials in the url", []string{"NETRA_LOKI_URL=http://u:p@loki:3100"}, 1},
		{"malformed labels", []string{"NETRA_LOKI_URL=http://loki:3100", "NETRA_LOKI_LABELS=cluster"}, 1},
		{"invalid label name", []string{"NETRA_LOKI_URL=http://loki:3100", "NETRA_LOKI_LABELS=bad-name=x"}, 1},
		{"label that Netra owns", []string{"NETRA_LOKI_URL=http://loki:3100", "NETRA_LOKI_LABELS=severity=x"}, 1},
		{"unknown class", []string{"NETRA_LOKI_URL=http://loki:3100", "NETRA_LOKI_CLASSES=audit,flows"}, 1},
		{"malformed headers", []string{"NETRA_LOKI_URL=http://loki:3100", "NETRA_LOKI_HEADERS=novalue"}, 1},
		{"username without password", []string{"NETRA_LOKI_URL=http://loki:3100", "NETRA_LOKI_USERNAME=u"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStartLokiFailsFastOnBadConfig$")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			cmd.Env = append(cleanLokiEnv(), append(tc.env, "NETRA_TEST_START_LOKI=1")...)
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("running child: %v", err)
			}
			if code != tc.want {
				t.Fatalf("exit code = %d, want %d", code, tc.want)
			}
		})
	}
}

func cleanLokiEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "NETRA_LOKI_") || strings.HasPrefix(kv, "NETRA_TEST_START_LOKI") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
