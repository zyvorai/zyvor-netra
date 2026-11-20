// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "testing"

func TestCaptureCmdRequiresSubcommand(t *testing.T) {
	if err := captureCmd(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureCmdUnknownSubcommand(t *testing.T) {
	if err := captureCmd([]string{"pcap"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureCmdStopRequiresNode(t *testing.T) {
	if err := captureCmd([]string{"stop"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureStartCmdRequiresNode(t *testing.T) {
	if err := captureCmd([]string{"start"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureStartCmdUnknownFlag(t *testing.T) {
	if err := captureCmd([]string{"start", "node-1", "--nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureStartCmdBadPort(t *testing.T) {
	if err := captureCmd([]string{"start", "node-1", "--port", "not-a-number"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureStartCmdBadDuration(t *testing.T) {
	if err := captureCmd([]string{"start", "node-1", "--duration", "not-a-duration"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureStartCmdMissingFlagValue(t *testing.T) {
	if err := captureCmd([]string{"start", "node-1", "--host"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureStartCmdBackendMissingValue(t *testing.T) {
	if err := captureCmd([]string{"start", "node-1", "--backend"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaptureStartCmdBackendUnknownValue(t *testing.T) {
	if err := captureCmd([]string{"start", "node-1", "--backend", "bogus"}); err == nil {
		t.Fatal("expected error")
	}
}
