// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// TestApplyCapture_AFPacketDoesNotRequireEBPFObject is the highest-value
// new test for the AF_PACKET capture backend: applyCapture's existing
// "capture_spec map unavailable" guard must apply only to backend: "ebpf"
// sessions — a backend: "afpacket" request must be dispatched to
// internal/afcapture instead, entirely bypassing that guard, even when no
// eBPF capture object/collection is attached at all (NETRA_CAPTURE=off, or
// load failed). This is the one place existing eBPF-path behavior was
// branched, not purely extended, so it needs a dedicated regression test
// rather than just trusting the code reading.
func TestApplyCapture_AFPacketDoesNotRequireEBPFObject(t *testing.T) {
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))} // no captureCollection at all
	desired := &models.CaptureSpec{
		Node: "n1", Backend: "afpacket", Protocol: "tcp",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	err := a.applyCapture(context.Background(), desired)
	if err == nil {
		t.Fatal("expected an error on this dev machine (no CAP_NET_RAW), but it must be the AF_PACKET-specific one below, not a false success")
	}
	// The real assertion: never the eBPF-path error message, regardless of
	// whether the AF_PACKET probe itself succeeds or fails on the machine
	// running the test.
	if strings.Contains(err.Error(), "capture_spec") {
		t.Fatalf("backend=afpacket must never hit the eBPF capture_spec-map guard, got: %v", err)
	}
	if a.captureBackendErr == "" || !strings.HasPrefix(a.captureBackendErr, "afpacket:") {
		t.Fatalf("expected captureBackendErr to be recorded with an afpacket: prefix, got %q", a.captureBackendErr)
	}
}

func TestApplyCapture_EBPFStillRequiresCaptureSpecMap(t *testing.T) {
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))} // no captureCollection
	desired := &models.CaptureSpec{
		Node: "n1", Backend: "ebpf", Protocol: "tcp",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	err := a.applyCapture(context.Background(), desired)
	if err == nil {
		t.Fatal("expected an error: no capture_spec map is attached")
	}
	if !strings.Contains(err.Error(), "capture_spec") {
		t.Fatalf("expected the eBPF capture_spec-map error, got: %v", err)
	}
	if !strings.HasPrefix(a.captureBackendErr, "ebpf:") {
		t.Fatalf("expected captureBackendErr to be recorded with an ebpf: prefix, got %q", a.captureBackendErr)
	}
}

func TestApplyCapture_UnknownBackendRejected(t *testing.T) {
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	desired := &models.CaptureSpec{
		Node: "n1", Backend: "bogus", Protocol: "tcp",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := a.applyCapture(context.Background(), desired); err == nil {
		t.Fatal("expected an error for an unrecognized backend value")
	}
}
