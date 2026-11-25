// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/beacon"
	"github.com/zyvorai/netra/internal/flowdrift"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/netpolcoverage"
	"github.com/zyvorai/netra/internal/store"
)

// beaconStore reports one check-in a minute, for half an hour, from a pod in
// each of two namespaces to a public peer. The counters are cumulative, so the
// first report is only a baseline.
func beaconStore(t *testing.T) *store.Store {
	t.Helper()
	st := store.New()
	now := time.Now().UTC()
	for i := 0; i <= 30; i++ {
		n := uint64(i + 1)
		st.Report(models.AgentReport{Node: "worker-1", ObservedAt: now.Add(time.Duration(i-31) * time.Minute), Stats: []models.DestinationStat{
			{DestinationIP: "203.0.113.7", Port: 443, Protocol: "TCP", Direction: "egress", Packets: n, Bytes: n * 500, Namespace: "shop", Pod: "api-1", WorkloadKind: "ReplicaSet", WorkloadName: "api-rs"},
			{DestinationIP: "203.0.113.8", Port: 443, Protocol: "TCP", Direction: "egress", Packets: n, Bytes: n * 500, Namespace: "other", Pod: "x-1", WorkloadName: "x-rs"},
		}})
	}
	return st
}

func serve(h http.HandlerFunc, path string, p *principal) (int, []byte) {
	req := httptest.NewRequest("GET", path, nil)
	if p != nil {
		req = req.WithContext(withPrincipal(context.Background(), *p))
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestSecurityBeaconsEndpoint(t *testing.T) {
	s := &Server{store: beaconStore(t), metricsData: &telemetry{}}
	code, body := serve(s.securityBeacons, "/api/v1/security/beacons", nil)
	var rep beacon.Report
	if code != 200 || json.Unmarshal(body, &rep) != nil || rep.Schema != beacon.Schema || !rep.Ready || rep.Total != 2 {
		t.Fatalf("%d %s", code, body)
	}
	if c := rep.Candidates[0]; c.PeriodSeconds != 60 || c.Events != 30 || c.MedianBytes != 500 {
		t.Fatalf("%+v", c)
	}
	code, body = serve(s.securityBeacons, "/api/v1/security/beacons?namespace=shop&min_events=31", nil)
	if code != 200 || json.Unmarshal(body, &rep) != nil || rep.Total != 0 || rep.MinEvents != 31 {
		t.Fatalf("%d %s", code, body)
	}
	for _, bad := range []string{"window=1m", "window=9999h", "window=x", "min_period=1s", "min_period=7h", "min_events=5", "min_events=x",
		"min_score=0.1", "min_score=1.5", "min_score=NaN", "limit=0", "limit=501"} {
		if code, _ := serve(s.securityBeacons, "/api/v1/security/beacons?"+bad, nil); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}

	// A namespace-scoped caller sees only its namespace and may not ask for another.
	p := &principal{kind: "oidc", Namespaces: []string{"shop"}}
	code, body = serve(s.securityBeacons, "/api/v1/security/beacons", p)
	if code != 200 || json.Unmarshal(body, &rep) != nil || rep.Total != 1 || rep.Candidates[0].Namespace != "shop" || strings.Contains(string(body), "203.0.113.8") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := serve(s.securityBeacons, "/api/v1/security/beacons?namespace=other", p); code != 403 {
		t.Fatal(code)
	}
}

func TestVolumeShiftBaselineMode(t *testing.T) {
	s := &Server{store: beaconStore(t), metricsData: &telemetry{}}
	code, body := serve(s.volumeShift, "/api/v1/insights/volume-shift?baseline_mode=same-time", nil)
	var sh flowdrift.ShiftReport
	if code != 200 || json.Unmarshal(body, &sh) != nil || sh.BaselineMode != flowdrift.ModeSameTime || sh.Ready || sh.NotReady == "" {
		t.Fatalf("%d %s", code, body)
	}
	code, body = serve(s.volumeShift, "/api/v1/insights/volume-shift?baseline_mode=average", nil)
	if code != 200 || json.Unmarshal(body, &sh) != nil || sh.BaselineMode != flowdrift.ModeAverage {
		t.Fatalf("%d %s", code, body)
	}
	for _, bad := range []string{"baseline_mode=weekly", "baseline_mode=same-time&recent=30h"} {
		if code, _ := serve(s.volumeShift, "/api/v1/insights/volume-shift?"+bad, nil); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}
}

type coverageKube struct {
	mu       sync.Mutex
	paths    []string
	denyPol  bool
	badItems bool
}

func (k *coverageKube) client(t *testing.T) *kube.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		defer k.mu.Unlock()
		if r.Method != http.MethodGet {
			t.Errorf("coverage must only read, got %s %s", r.Method, r.URL.Path)
		}
		k.paths = append(k.paths, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/networkpolicies"):
			if k.denyPol {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"reason":"Forbidden"}`)
				return
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
		case k.badItems:
			_, _ = io.WriteString(w, `{"items":["nope"]}`)
		case r.URL.Path == "/api/v1/pods":
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"namespace":"shop","name":"api-1","ownerReferences":[{"kind":"ReplicaSet","name":"api-rs","controller":true}]}},{"metadata":{"namespace":"other","name":"x-1"}}]}`)
		case r.URL.Path == "/api/v1/namespaces/shop/pods":
			_, _ = io.WriteString(w, `{"items":[{"metadata":{"namespace":"shop","name":"api-1","ownerReferences":[{"kind":"ReplicaSet","name":"api-rs","controller":true}]}}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return kube.NewForTesting(ts.URL, ts.Client())
}

func TestNetpolCoverageEndpoint(t *testing.T) {
	k := &coverageKube{}
	s := &Server{store: beaconStore(t), metricsData: &telemetry{}, kube: k.client(t), log: slog.New(slog.DiscardHandler)}
	code, body := serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage", nil)
	var rep netpolcoverage.Report
	if code != 200 || json.Unmarshal(body, &rep) != nil || rep.Schema != netpolcoverage.Schema || rep.Total != 2 {
		t.Fatalf("%d %s", code, body)
	}
	if w := rep.Workloads[1]; w.Name != "api-rs" || !w.Attention || w.PublicEgress.Peers != 1 || w.Status != netpolcoverage.Uncovered {
		t.Fatalf("%+v", w)
	}
	if got := strings.Join(k.paths, " "); got != "/api/v1/pods /apis/networking.k8s.io/v1/networkpolicies" {
		t.Fatal(got)
	}

	// A scoped caller lists only its own namespaces.
	k.paths = nil
	p := &principal{kind: "oidc", Namespaces: []string{"shop"}}
	code, body = serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage", p)
	if code != 200 || json.Unmarshal(body, &rep) != nil || rep.Total != 1 || strings.Contains(string(body), "203.0.113.8") {
		t.Fatalf("%d %s", code, body)
	}
	if got := strings.Join(k.paths, " "); got != "/api/v1/namespaces/shop/pods /apis/networking.k8s.io/v1/namespaces/shop/networkpolicies" {
		t.Fatal(got)
	}
	if code, _ := serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage?namespace=other", p); code != 403 {
		t.Fatal(code)
	}
	// A scope with an empty or repeated entry never widens to the whole cluster.
	k.paths = nil
	code, body = serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage", &principal{kind: "service", Namespaces: []string{"", "shop", " shop"}})
	if code != 200 || strings.Join(k.paths, " ") != "/api/v1/namespaces/shop/pods /apis/networking.k8s.io/v1/namespaces/shop/networkpolicies" {
		t.Fatalf("%d %v %s", code, k.paths, body)
	}
	k.paths = nil
	code, body = serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage", &principal{kind: "service", Namespaces: []string{""}})
	if code != 200 || len(k.paths) != 0 || strings.Contains(string(body), "api-rs") {
		t.Fatalf("%d %v %s", code, k.paths, body)
	}
	for _, bad := range []string{"window=1s", "window=9999h", "limit=0", "limit=1001"} {
		if code, _ := serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage?"+bad, nil); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}

	k.denyPol = true
	code, body = serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage", nil)
	if code != 502 || !strings.Contains(string(body), "networking.k8s.io networkpolicies") {
		t.Fatalf("a missing permission must fail, not report everything open: %d %s", code, body)
	}
	k.denyPol, k.badItems = false, true
	if code, body = serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage", nil); code != 502 {
		t.Fatalf("%d %s", code, body)
	}
	s.kube = nil
	if code, _ = serve(s.netpolCoverage, "/api/v1/insights/netpol-coverage", nil); code != 503 {
		t.Fatal(code)
	}
}
