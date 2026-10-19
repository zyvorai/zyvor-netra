// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/chatops"
)

// TestRegisteredAPIRoutes ensures critical mux patterns stay wired.
// Requests intentionally omit the API token so auth returns 401 instead of
// exercising nil kube/store dependencies — anything other than 404 proves registration.
func TestRegisteredAPIRoutes(t *testing.T) {
	s := &Server{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:        "ci-test-token",
		metricsData:   &telemetry{},
		ciliumEnabled: true,
	}
	h := s.Handler()
	paths := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/features"},
		{"POST", "/api/v1/features/dns-detect"},
		{"GET", "/api/v1/pods"},
		{"GET", "/api/v1/vms"},
		{"GET", "/api/v1/workloads/pod/default/demo"},
		{"POST", "/api/v1/policies/simulate"},
		{"POST", "/api/v1/policies/lockdown"},
		{"DELETE", "/api/v1/policies/lockdown/default/demo"},
		{"GET", "/api/v1/policies/gitops/status"},
		{"POST", "/api/v1/policies/gitops/resync"},
		{"GET", "/api/v1/flows/summary"},
		{"GET", "/api/v1/flows/history"},
		{"GET", "/api/v1/insights/summary"},
		{"GET", "/api/v1/insights/dependencies"},
		{"GET", "/api/v1/insights/baseline"},
		{"GET", "/api/v1/insights/drift"},
		{"GET", "/api/v1/insights/recommendations"},
		{"GET", "/api/v1/insights/rates"},
		{"GET", "/api/v1/insights/rate-baseline"},
		{"GET", "/api/v1/insights/rate-drift"},
		{"GET", "/api/v1/insights/exposure"},
		{"GET", "/api/v1/insights/blast-radius"},
		{"GET", "/api/v1/insights/health-trend"},
		{"GET", "/api/v1/insights/policy-review"},
		{"GET", "/api/v1/insights/new-since-start"},
		{"GET", "/api/v1/insights/protocol-downgrades"},
		{"GET", "/api/v1/insights/remediations"},
		{"GET", "/api/v1/incidents"},
		{"GET", "/api/v1/incidents/timeline"},
		{"GET", "/api/v1/export/audit"},
		{"GET", "/api/v1/export/events"},
		{"GET", "/api/v1/export/flows"},
		{"GET", "/api/v1/export/blocks"},
		{"GET", "/api/v1/export/status"},
		{"GET", "/api/v1/report"},
		{"GET", "/api/v1/playbooks"},
		{"GET", "/api/v1/audit/summary"},
		{"POST", "/api/v1/intel/preview"},
		{"GET", "/api/v1/intel/feed"},
		{"PUT", "/api/v1/intel/feed"},
		{"DELETE", "/api/v1/intel/feed"},
		{"GET", "/api/v1/intel/hits"},
		{"POST", "/api/v1/intel/apply"},
		{"GET", "/api/v1/ebpf/ai-destinations"},
		{"POST", "/api/v1/ebpf/ai-destinations/deny"},
		{"GET", "/api/v1/ebpf/app-categories"},
		{"GET", "/api/v1/ebpf/auto-mitigate"},
		{"GET", "/api/v1/compliance"},
		{"POST", "/api/v1/ebpf/deny/preview"},
		{"POST", "/api/v1/ebpf/deny/preview-history"},
		{"GET", "/api/v1/ebpf/dns-findings"},
		{"GET", "/api/v1/ebpf/scan-findings"},
		{"GET", "/api/v1/ebpf/coverage"},
		{"GET", "/api/v1/fleet"},
		{"GET", "/api/v1/fleet/clusters"},
		{"GET", "/api/v1/fleet/flows/history"},
		{"POST", "/api/v1/investigate/connection"},
		{"GET", "/api/v1/investigate/connection"},
		{"GET", "/api/v1/fleet/tenants"},
		{"GET", "/api/v1/ebpf/tls-fingerprints"},
		{"GET", "/api/v1/ebpf/tls-fingerprints/risk"},
		{"GET", "/api/v1/ebpf/encrypted-dns"},
		{"GET", "/api/v1/insights/zero-trust"},
		{"GET", "/api/v1/insights/microseg"},
		{"GET", "/api/v1/insights/shadow-saas"},
		{"GET", "/api/v1/insights/experience"},
		{"GET", "/api/v1/insights/red"},
		{"GET", "/api/v1/insights/traces"},
		{"GET", "/api/v1/insights/profiles"},
		{"GET", "/api/v1/insights/workload-events"},
		{"GET", "/api/v1/insights/kernel-notes"},
		{"GET", "/api/v1/insights/destination-risk"},
		{"GET", "/api/v1/insights/policy-packs"},
		{"GET", "/api/v1/insights/identity-drafts"},
		{"GET", "/api/v1/insights/ech-blind"},
		{"GET", "/api/v1/insights/exfil"},
		{"GET", "/api/v1/insights/lateral"},
		{"GET", "/api/v1/insights/category-deny"},
		{"GET", "/api/v1/intel/dns-hits"},
		{"GET", "/api/v1/report/prevention"},
		{"GET", "/api/v1/node-resources"},
		{"GET", "/api/v1/handoff"},
		{"GET", "/api/v1/scorecard"},
		{"GET", "/api/v1/ebpf/reasons"},
		{"GET", "/api/v1/talkers"},
		{"POST", "/api/v1/watchlist/match"},
		{"GET", "/api/v1/namespaces/heat"},
		{"GET", "/api/v1/protocols"},
		{"GET", "/api/v1/ebpf/census"},
		{"GET", "/api/v1/ebpf/maps"},
		{"GET", "/api/v1/baselines"},
		{"GET", "/api/v1/ports"},
		{"GET", "/api/v1/dns/board"},
		{"GET", "/api/v1/lease"},
		{"GET", "/api/v1/ai/status"},
		{"GET", "/api/v1/ai/brief"},
		{"POST", "/api/v1/ai/ask"},
		{"POST", "/api/v1/ai/draft"},
		{"GET", "/api/v1/ai/digest"},
		{"GET", "/api/v1/ai/suggestions"},
		{"POST", "/api/v1/ai/explain"},
		{"POST", "/api/v1/ai/agent"},
		{"GET", "/api/v1/ebpf/summary"},
		{"GET", "/api/v1/ebpf/health"},
		{"GET", "/api/v1/ebpf/capdrift"},
		{"GET", "/api/v1/ebpf/nsdrift"},
		{"GET", "/api/v1/ebpf/exehash"},
		{"GET", "/api/v1/ebpf/auto-mitigate/preview"},
		{"GET", "/api/v1/ebpf/stack-histograms"},
		{"GET", "/api/v1/capture/summaries"},
		{"GET", "/api/v1/ebpf/l7"},
		{"GET", "/api/v1/ebpf/path"},
		{"GET", "/api/v1/ebpf/drops"},
		{"GET", "/api/v1/ebpf/kernel-network"},
		{"GET", "/api/v1/netlink"},
		{"GET", "/api/v1/netlink/findings"},
		{"GET", "/api/v1/ebpf/attachments"},
		{"GET", "/api/v1/ebpf/diagnose"},
		{"POST", "/api/v1/ebpf/sni"},
		{"POST", "/api/v1/ebpf/allow"},
		{"DELETE", "/api/v1/ebpf/allow/1.2.3.4"},
		{"POST", "/api/v1/ebpf/allow-cidr"},
		{"POST", "/api/v1/ebpf/allow-cidr/delete"},
		{"POST", "/api/v1/ebpf/allow-port"},
		{"POST", "/api/v1/ebpf/allow-port/delete"},
		{"POST", "/api/v1/ebpf/allow-uid"},
		{"DELETE", "/api/v1/ebpf/allow-uid/1000"},
		{"POST", "/api/v1/ebpf/allow-process"},
		{"POST", "/api/v1/ebpf/allow-process/delete"},
		{"PUT", "/api/v1/ebpf/shield"},
		{"PUT", "/api/v1/ebpf/netpol/config"},
		{"PUT", "/api/v1/ebpf/netpol/v2/config"},
		{"POST", "/api/v1/ebpf/netpol/rules"},
		{"DELETE", "/api/v1/ebpf/netpol/rules/netpolrule-1"},
		{"POST", "/api/v1/ebpf/conn-rate-limit"},
		{"DELETE", "/api/v1/ebpf/conn-rate-limit/connratelimit-1"},
		{"POST", "/api/v1/ebpf/netpol/default-deny/plan"},
		{"PUT", "/api/v1/ebpf/netpol/default-deny"},
		{"GET", "/api/v1/ebpf/rules"},
		{"GET", "/api/v1/ebpf/rules/ip4-1"},
		{"PATCH", "/api/v1/ebpf/rules/ip4-1"},
		{"DELETE", "/api/v1/ebpf/rules/ip4-1"},
		{"GET", "/api/v1/ebpf/rules/ip4-1/history"},
		{"POST", "/api/v1/ebpf/rules/ip4-1/rollback/1"},
		{"GET", "/api/v1/ebpf/capabilities"},
		{"GET", "/api/v1/ebpf/workloads"},
		{"GET", "/api/v1/ebpf/topology"},
		{"PUT", "/api/v1/vms/node-1/capture"},
		{"DELETE", "/api/v1/vms/node-1/capture"},
		{"GET", "/api/v1/vms/node-1/capture/ws"},
		{"GET", "/api/v1/capture/status"},
		{"GET", "/api/v1/capture/history"},
		{"GET", "/api/v1/capture/artifacts/x/context"},
		{"GET", "/api/v1/capture/artifacts/x"},
		{"POST", "/api/v1/capture/bulk"},
		{"GET", "/livez"},
	}
	for _, tc := range paths {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("%s %s returned 404; route missing", tc.method, tc.path)
		}
		if tc.path == "/livez" {
			if rec.Code != http.StatusOK {
				t.Fatalf("livez status %d", rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: want 401 without token, got %d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

// TestChatOpsRouteRegisteredOnlyWhenConfigured confirms /chatops/slack is
// absent unless chatopsHandler is set (chatops.NewHandler in New() requires
// a signing secret), and rejects unsigned requests with 401 rather than the
// bearer-token 401 every other route above uses — chatops.VerifySlackSignature
// is this route's actual authentication, not s.auth's bearer token.
func TestChatOpsRouteRegisteredOnlyWhenConfigured(t *testing.T) {
	bare := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
	}
	req := httptest.NewRequest("POST", "/chatops/slack", nil)
	rec := httptest.NewRecorder()
	bare.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("without a configured chatopsHandler, want 404, got %d", rec.Code)
	}

	wired := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		chatopsHandler: chatops.NewHandler(chatops.Config{
			SigningSecret: "shh",
			Client:        chatops.NewClient("http://127.0.0.1:0", "k"),
		}),
	}
	req = httptest.NewRequest("POST", "/chatops/slack", nil)
	rec = httptest.NewRecorder()
	wired.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatal("with a configured chatopsHandler, route must be registered")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request: want 401 from VerifySlackSignature, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestChatOpsTeamsRouteRegisteredOnlyWhenConfigured mirrors
// TestChatOpsRouteRegisteredOnlyWhenConfigured above for the Teams route:
// absent (404) unless chatopsTeamsHandler is set (chatops.NewTeamsHandler
// in New() requires a Microsoft App ID), and 401 for a request with no
// bearer token at all — that check happens before any JWT verification, so
// this needs no real Bot Framework JWKS endpoint reachable in tests.
func TestChatOpsTeamsRouteRegisteredOnlyWhenConfigured(t *testing.T) {
	bare := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
	}
	req := httptest.NewRequest("POST", "/chatops/teams", nil)
	rec := httptest.NewRecorder()
	bare.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("without a configured chatopsTeamsHandler, want 404, got %d", rec.Code)
	}

	wired := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		chatopsTeamsHandler: chatops.NewTeamsHandler(chatops.TeamsConfig{
			AppID:  "app-1",
			Client: chatops.NewClient("http://127.0.0.1:0", "k"),
		}),
	}
	req = httptest.NewRequest("POST", "/chatops/teams", nil)
	rec = httptest.NewRecorder()
	wired.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatal("with a configured chatopsTeamsHandler, route must be registered")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("request with no bearer token: want 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}
