// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/scandetect"
)

func TestEBPFDNSFindingsDisabledWithoutDetector(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/api/v1/ebpf/dns-findings", nil)
	rec := httptest.NewRecorder()
	s.ebpfDNSFindings(rec, r)
	if rec.Code != 409 {
		t.Fatalf("status=%d, want 409 (dns-detect not enabled)", rec.Code)
	}
}

func TestEBPFDNSFindingsReturnsDetectorState(t *testing.T) {
	s := &Server{dnsDetector: dnsdetect.New(dnsdetect.DefaultConfig())}
	r := httptest.NewRequest("GET", "/api/v1/ebpf/dns-findings", nil)
	rec := httptest.NewRecorder()
	s.ebpfDNSFindings(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Findings []dnsdetect.Finding `json:"findings"`
		Snapshot dnsdetect.Snapshot  `json:"snapshot"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v, body=%s", err, rec.Body.String())
	}
}

func TestEBPFScanFindingsDisabledWithoutDetector(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/api/v1/ebpf/scan-findings", nil)
	rec := httptest.NewRecorder()
	s.ebpfScanFindings(rec, r)
	if rec.Code != 409 {
		t.Fatalf("status=%d, want 409 (scan-detect not enabled)", rec.Code)
	}
}

func TestEBPFScanFindingsReturnsDetectorState(t *testing.T) {
	s := &Server{scanDetector: scandetect.New(scandetect.DefaultConfig())}
	r := httptest.NewRequest("GET", "/api/v1/ebpf/scan-findings", nil)
	rec := httptest.NewRecorder()
	s.ebpfScanFindings(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Findings []scandetect.Finding `json:"findings"`
		Snapshot scandetect.Snapshot  `json:"snapshot"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v, body=%s", err, rec.Body.String())
	}
}
