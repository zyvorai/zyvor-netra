// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/store"
)

func newNetPolTestServer() *Server {
	return &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
	}
}

func postNetPolRule(t *testing.T, h http.Handler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/ebpf/netpol/rules", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestEBPFNetPolRulePortOnlyAccepted guards the port-only allow-exception:
// an empty peerIpv4 with a nonzero port is a legitimate rule (any peer,
// exact port), mirroring the v1 flat engine's allowed_ports mechanism.
func TestEBPFNetPolRulePortOnlyAccepted(t *testing.T) {
	s := newNetPolTestServer()
	h := s.Handler()

	rec := postNetPolRule(t, h, map[string]any{
		"selector":  map[string]any{"namespace": "default"},
		"port":      8080,
		"protocol":  "TCP",
		"direction": "egress",
		"action":    "allow",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST netpol rule (port-only): want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var cfg struct {
		NetPolRules []struct {
			PeerIPv4 string `json:"peerIpv4"`
			Port     uint16 `json:"port"`
		} `json:"netPolRules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.NetPolRules) != 1 || cfg.NetPolRules[0].PeerIPv4 != "" || cfg.NetPolRules[0].Port != 8080 {
		t.Fatalf("port-only rule not recorded as expected: %+v", cfg.NetPolRules)
	}
}

// TestEBPFNetPolRuleRejectsEmptyPeerAndPort guards against a rule with
// neither an exact peer nor an exact port — it would have no discriminator
// for netpol_v2_lookup4's three-step fallback to match against.
func TestEBPFNetPolRuleRejectsEmptyPeerAndPort(t *testing.T) {
	s := newNetPolTestServer()
	h := s.Handler()

	rec := postNetPolRule(t, h, map[string]any{
		"selector":  map[string]any{"namespace": "default"},
		"direction": "egress",
		"action":    "allow",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST netpol rule (no peer, no port): want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestEBPFNetPolRuleExactPeerStillRequiresValidIPv4 confirms a non-empty
// peer is still validated as an exact IPv4 address, unchanged from before
// port-only rules existed.
func TestEBPFNetPolRuleExactPeerStillRequiresValidIPv4(t *testing.T) {
	s := newNetPolTestServer()
	h := s.Handler()

	rec := postNetPolRule(t, h, map[string]any{
		"selector":  map[string]any{"namespace": "default"},
		"peerIpv4":  "not-an-ip",
		"direction": "egress",
		"action":    "allow",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST netpol rule (bad peer): want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
