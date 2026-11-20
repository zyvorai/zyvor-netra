// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/workloadobs"
)

// buildWorkloadObs exits the process on malformed config so an SLO is never
// silently ignored. os.Exit cannot be observed in-process, so each case
// re-executes the test binary and reports what it built on stdout.
func TestBuildWorkloadObsFailsFastOnBadConfig(t *testing.T) {
	if os.Getenv("NETRA_TEST_BUILD_WOBS") == "1" {
		if o := buildWorkloadObs(slog.New(slog.NewTextHandler(io.Discard, nil))); o == nil {
			os.Stdout.WriteString("nil")
		} else {
			os.Stdout.WriteString("observer")
		}
		os.Exit(0)
	}
	goodSLO := `[{"name":"checkout","namespace":"shop","workload":"Deployment/checkout","sli":"http_5xx","targetPct":99.9}]`
	cases := []struct {
		name     string
		env      []string
		wantExit int
		wantOut  string
	}{
		{"everything off by default", nil, 0, "nil"},
		{"workload series on", []string{"NETRA_METRICS_WORKLOAD_LABELS=on"}, 0, "observer"},
		{"an SLO alone enables it", []string{"NETRA_SLO_DEFINITIONS=" + goodSLO}, 0, "observer"},
		{"helm-style numeric string targetPct", []string{`NETRA_SLO_DEFINITIONS=[{"name":"a","sli":"http_5xx","targetPct":"99.9"}]`}, 0, "observer"},
		{"labels garbage", []string{"NETRA_METRICS_WORKLOAD_LABELS=sometimes"}, 1, ""},
		{"max too large", []string{"NETRA_METRICS_WORKLOAD_LABELS=on", "NETRA_METRICS_WORKLOAD_MAX=100000"}, 1, ""},
		{"interval too short", []string{"NETRA_METRICS_WORKLOAD_LABELS=on", "NETRA_WORKLOAD_OBS_INTERVAL=1s"}, 1, ""},
		{"slo is not JSON", []string{"NETRA_SLO_DEFINITIONS=checkout 99.9"}, 1, ""},
		{"slo with an unknown sli", []string{`NETRA_SLO_DEFINITIONS=[{"name":"a","sli":"latency_p99","targetPct":99}]`}, 1, ""},
		{"slo with an impossible target", []string{`NETRA_SLO_DEFINITIONS=[{"name":"a","sli":"http_5xx","targetPct":100}]`}, 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBuildWorkloadObsFailsFastOnBadConfig$")
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Env = append(cleanWobsEnv(), append(tc.env, "NETRA_TEST_BUILD_WOBS=1")...)
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
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Fatalf("stdout = %q, want %q", out.String(), tc.wantOut)
			}
		})
	}
}

func cleanWobsEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "NETRA_METRICS_WORKLOAD_") || strings.HasPrefix(kv, "NETRA_SLO_") ||
			strings.HasPrefix(kv, "NETRA_WORKLOAD_OBS_") || strings.HasPrefix(kv, "NETRA_TEST_BUILD_WOBS") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func TestStartWorkloadObsIsOffWithoutAnObserver(t *testing.T) {
	var wg sync.WaitGroup
	if stop := startWorkloadObs(context.Background(), slog.Default(), store.New(), nil, &wg); stop != nil {
		t.Fatal("startWorkloadObs must be a no-op without an observer")
	}
}

// The loop must really read agent reports from the store, and stop on cancel
// (the HA demote path relies on that to release the leader-only loop).
func TestStartWorkloadObsFoldsInStoreReportsAndStopsOnCancel(t *testing.T) {
	st := store.New()
	st.Report(models.AgentReport{
		Node: "n1", ObservedAt: time.Now().UTC(),
		Stats: []models.DestinationStat{{
			CgroupID: 9, Namespace: "shop", WorkloadKind: "Deployment", WorkloadName: "web",
			Hook: "egress", Direction: "egress", Protocol: "tcp", DestinationIP: "10.0.0.2", Port: 80, Packets: 5, Bytes: 5,
		}},
	})
	o, err := workloadobs.NewObserver(workloadobs.Config{PromSeries: true})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := startWorkloadObs(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), st, o, &wg)
	if stop == nil {
		t.Fatal("startWorkloadObs returned nil for a real observer")
	}
	// The first tick runs immediately and baselines the report's one entry.
	waitFor(t, "the observer to read the store's agent report", func() bool { return o.Snapshot().Entries == 1 })

	stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the observer loop did not exit after cancel")
	}
}
