// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/store"
)

func TestEBPFDenyPreviewHistoryCIDR(t *testing.T) {
	s := &Server{store: store.New()}
	body := `{"kind":"cidr","value":"203.0.113.0/24","direction":"egress","since":"1h"}`
	r := httptest.NewRequest("POST", "/api/v1/ebpf/deny/preview-history", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	s.ebpfDenyPreviewHistory(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out denyHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Result == nil || out.Since != "1h" || out.Caveat == "" {
		t.Fatalf("unexpected: %+v", out)
	}
	if out.Result.FlowsSeen != 0 {
		t.Fatalf("empty store flowsSeen=%d", out.Result.FlowsSeen)
	}
}

func TestEBPFDenyPreviewHistoryRejectsProcess(t *testing.T) {
	s := &Server{store: store.New()}
	body := `{"kind":"process","value":"curl","since":"1h"}`
	r := httptest.NewRequest("POST", "/api/v1/ebpf/deny/preview-history", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	s.ebpfDenyPreviewHistory(rec, r)
	if rec.Code != 400 {
		t.Fatalf("status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}
}

func TestParseHistorySince(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	start, label, err := parseHistorySince("", now)
	if err != nil || label != "1h" || !start.Equal(now.Add(-time.Hour)) {
		t.Fatalf("default: start=%v label=%s err=%v", start, label, err)
	}
	_, _, err = parseHistorySince("720h", now)
	if err == nil {
		t.Fatal("expected error for >7d")
	}
}
