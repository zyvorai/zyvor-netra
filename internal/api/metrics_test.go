// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

// TestMetricsFastpathGauges guards the Prometheus gauges added for the
// allow-side and ingress-deny fast-path maps (allowed_v4/v6, allowed_cidr_v4/v6,
// allowed_ports, blocked_ingress_v4/v6): they must reflect the live store config counts.
func TestMetricsFastpathGauges(t *testing.T) {
	st := store.New()
	if _, err := st.AddAllowed("203.0.113.5", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddAllowedIPv6("2001:db8::5", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddAllowedCIDR(models.EBPFCIDRRule{CIDR: "10.5.0.0/16", Direction: "both"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddAllowedPort(models.EBPFPortRule{Protocol: "TCP", Port: 443, Direction: "egress"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddBlockedIngress("198.51.100.9", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddBlockedIngressIPv6("2001:db8::9", "test"); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		metricsData: &telemetry{},
		store:       st,
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	s.metrics(rec, req)

	body := rec.Body.String()
	want := map[string]string{
		"netra_fastpath_allowed_ipv4 ":         "1",
		"netra_fastpath_allowed_ipv6 ":         "1",
		"netra_fastpath_allowed_cidrs ":        "1",
		"netra_fastpath_allowed_ports ":        "1",
		"netra_fastpath_blocked_ingress_ipv4 ": "1",
		"netra_fastpath_blocked_ingress_ipv6 ": "1",
	}
	for _, line := range strings.Split(body, "\n") {
		for prefix, val := range want {
			if strings.HasPrefix(line, prefix) {
				if strings.TrimSpace(strings.TrimPrefix(line, prefix)) != val {
					t.Fatalf("unexpected value for %q: line=%q", prefix, line)
				}
				delete(want, prefix)
			}
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing metric lines: %v\nbody=%s", want, body)
	}
}

func TestMetricsKernelNetworkRates(t *testing.T) {
	st := store.New()
	now := time.Now().UTC()
	boot := now.Add(-time.Hour)
	st.Report(apiKernelReport(now.Add(-time.Minute), boot, 100))
	st.Report(apiKernelReport(now, boot, 106))
	s := &Server{store: st, metricsData: &telemetry{}, agentStaleAfter: 2 * time.Minute}
	rec := httptest.NewRecorder()
	s.metrics(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"netra_kernel_network_findings 1",
		"netra_kernel_network_warming_nodes 0",
		"netra_udp_receive_buffer_error_rate 0.100000",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in metrics:\n%s", want, body)
		}
	}
}
