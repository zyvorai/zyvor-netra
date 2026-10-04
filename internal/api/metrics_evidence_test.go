// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestEvidenceKinds(t *testing.T) {
	for ctx, want := range map[string]string{
		"ebpf.kernel_drops":   "drops",
		"net.softnet_stat":    "drops",
		"ip.tcp_retransmits":  "tcp",
		"workload.red_errors": "tcp",
		"workload.red_dns":    "dns",
		"workload.red_http":   "http",
		"nginx.requests":      "http",
		"netfilter.conntrack": "conntrack",
		"net.net":             "flows",
		"workload.red_rate":   "flows",
		"cgroup.cpu":          "flows",
	} {
		if got := evidenceKinds(ctx)[0]; got != want {
			t.Errorf("%s: %s, want %s", ctx, got, want)
		}
	}
}

func TestMetricsEvidenceJoinsFlowsDropsAndCaptures(t *testing.T) {
	s, h := metricsTestServer(t)
	now := time.Now().UTC()
	report := func(at time.Time, scale uint64) models.AgentReport {
		return models.AgentReport{Node: "n1", ObservedAt: at,
			Stats: []models.DestinationStat{
				{DestinationIP: "10.0.0.9", Port: 5432, Protocol: "tcp", Namespace: "shop", Pod: "cart-1", WorkloadName: "cart", Packets: 100 * scale, Bytes: 1000 * scale, Blocked: 5 * scale},
				{DestinationIP: "10.0.0.7", Port: 443, Protocol: "tcp", Namespace: "shop", Pod: "web-1", WorkloadName: "web", Packets: 900 * scale, Bytes: 90000 * scale},
			},
			KernelDrops: []models.KernelDropStat{{Reason: 2, ReasonName: "NOT_SPECIFIED", Count: 7}, {Reason: 5, ReasonName: "NETFILTER_DROP", Count: 40}},
		}
	}
	s.store.Report(report(now.Add(-2*time.Minute), 1))
	s.store.Report(report(now.Add(-time.Minute), 3))
	s.store.SetCapture(models.CaptureSpec{Node: "n1", Protocol: "tcp", Port: 5432, ExpiresAt: now.Add(time.Minute)}, "alice")
	s.store.ClearCapture("n1", "alice", "manual")

	code, body := authedGet(t, h, "/api/v1/metrics/evidence?context=ebpf.kernel_drops&node=n1&after=-600")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	peers := body["topPeers"].([]any)
	if len(peers) != 2 || peers[0].(map[string]any)["peer"] != "10.0.0.9" {
		t.Fatalf("drops should rank the blocked peer first: %v", peers)
	}
	drops := body["kernelDrops"].([]any)
	if drops[0].(map[string]any)["name"] != "NETFILTER_DROP" {
		t.Fatalf("drops %v", drops)
	}
	if len(body["captures"].([]any)) != 1 {
		t.Fatalf("captures %v", body["captures"])
	}
	var hrefs []string
	for _, l := range body["links"].([]any) {
		hrefs = append(hrefs, l.(map[string]any)["href"].(string))
	}
	joined := strings.Join(hrefs, " ")
	for _, want := range []string{"/api/v1/drops/explain?node=n1", "/api/v1/flows/history?", "/api/v1/metrics/anomalies?"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing link %s in %s", want, joined)
		}
	}

	// Workload labels from a chart narrow flows to that workload.
	code, body = authedGet(t, h, "/api/v1/metrics/evidence?context=workload.red_rate&labels=namespace:shop,workload:web&after=-600")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, body)
	}
	peers = body["topPeers"].([]any)
	if len(peers) != 1 || peers[0].(map[string]any)["workload"] != "web" || body["kernelDrops"] != nil {
		t.Fatalf("workload evidence %v", body)
	}

	for _, q := range []string{"", "?context=x&after=-10&before=-20", "?context=x&after=-900000"} {
		if code, _ := authedGet(t, h, "/api/v1/metrics/evidence"+q); code != http.StatusBadRequest {
			t.Errorf("%q: %d, want 400", q, code)
		}
	}
}
