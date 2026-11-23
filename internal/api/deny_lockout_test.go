// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/denysim"
	"github.com/zyvorai/netra/internal/store"
)

func TestDenyPreviewReportsLockout(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	t.Setenv("NETRA_PROTECTED_DESTINATIONS", "198.51.100.0/24")
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), apiKey: "k", metricsData: &telemetry{}, store: store.New()}
	h := s.Handler()
	cases := []struct {
		body string
		code int
		risk string
	}{
		{`{"kind":"ip","value":"203.0.113.9"}`, 200, denysim.RiskNoneDetected},
		{`{"kind":"ip","value":"10.96.0.1"}`, 200, denysim.RiskLikely},
		{`{"kind":"cidr","value":"198.51.100.0/25"}`, 200, denysim.RiskLikely},
		{`{"kind":"port","value":"53"}`, 200, denysim.RiskLikely},
		{`{"kind":"cidr","value":"10.0.0.0/99"}`, 400, ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/api/v1/ebpf/deny/preview", bytes.NewBufferString(c.body))
		req.Header.Set("Authorization", "Bearer k")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Fatalf("%s: %d %s", c.body, rec.Code, rec.Body)
		}
		if c.code != http.StatusOK {
			continue
		}
		var out denysim.Result
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Lockout == nil || out.Lockout.Risk != c.risk {
			t.Fatalf("%s: lockout=%+v err=%v", c.body, out.Lockout, err)
		}
	}
}

func TestDenyPreviewIgnoresBadProtectedList(t *testing.T) {
	t.Setenv("NETRA_PROTECTED_DESTINATIONS", "bad name!")
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), apiKey: "k", metricsData: &telemetry{}, store: store.New()}
	req := httptest.NewRequest("POST", "/api/v1/ebpf/deny/preview", bytes.NewBufferString(`{"kind":"ip","value":"203.0.113.9"}`))
	req.Header.Set("Authorization", "Bearer k")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out denysim.Result
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Lockout == nil || out.Lockout.Caveat[:len("NETRA_PROTECTED")] != "NETRA_PROTECTED" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
