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

func newCaptureTestServer() (*Server, http.Handler) {
	s := &Server{
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		apiKey:      "ci-test-token",
		metricsData: &telemetry{},
		store:       store.New(),
		captureHub:  newCaptureHub(),
	}
	return s, s.Handler()
}

func doCaptureStart(t *testing.T, h http.Handler, node string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/api/v1/vms/"+node+"/capture", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer ci-test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestCaptureStart_AFPacketRequiresFilter confirms the existing "at least
// one of protocol/host/port is required" rule (unfiltered whole-interface
// captures are not allowed) applies identically to backend: "afpacket",
// not just the eBPF default — this rule runs before any backend dispatch,
// so it must never accidentally become backend-specific in a future
// refactor. See internal/api/capture.go's captureStart.
func TestCaptureStart_AFPacketRequiresFilter(t *testing.T) {
	_, h := newCaptureTestServer()
	rec := doCaptureStart(t, h, "node-1", map[string]any{"backend": "afpacket"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unfiltered afpacket capture: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCaptureStart_EBPFStillRequiresFilter(t *testing.T) {
	_, h := newCaptureTestServer()
	rec := doCaptureStart(t, h, "node-1", map[string]any{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unfiltered default-backend capture: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCaptureStart_UnknownBackendRejected(t *testing.T) {
	_, h := newCaptureTestServer()
	rec := doCaptureStart(t, h, "node-1", map[string]any{"backend": "bogus", "protocol": "tcp"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown backend: want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestCaptureStart_BackendDefaultsToEBPF confirms an omitted backend field
// (every pre-AF_PACKET caller: CLI without --backend, MCP without backend,
// old frontend builds) still works and is recorded as the default "ebpf",
// not left blank in a way a client would need to special-case.
func TestCaptureStart_BackendDefaultsToEBPF(t *testing.T) {
	_, h := newCaptureTestServer()
	rec := doCaptureStart(t, h, "node-1", map[string]any{"protocol": "tcp"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var spec struct {
		Backend string `json:"backend"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Backend != "ebpf" {
		t.Fatalf("expected backend to default to ebpf, got %q", spec.Backend)
	}
}

func TestCaptureStart_AFPacketBackendRecorded(t *testing.T) {
	_, h := newCaptureTestServer()
	rec := doCaptureStart(t, h, "node-1", map[string]any{"protocol": "tcp", "backend": "afpacket"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var spec struct {
		Backend string `json:"backend"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Backend != "afpacket" {
		t.Fatalf("expected backend=afpacket to be recorded, got %q", spec.Backend)
	}
}
