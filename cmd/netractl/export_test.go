// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import "testing"

func TestExportCmdRequiresKind(t *testing.T) {
	if err := exportCmd(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestExportCmdUnknownKind(t *testing.T) {
	if err := exportCmd([]string{"pcap"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExportCmdUnknownFlag(t *testing.T) {
	if err := exportCmd([]string{"audit", "--nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestReportCmdUnknownFlag(t *testing.T) {
	if err := reportCmd([]string{"--nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestIntelCmdRequiresPreviewFile(t *testing.T) {
	if err := intelCmd(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestPlaybooksCmdUnknownFlag(t *testing.T) {
	if err := playbooksCmd([]string{"--nope"}); err == nil {
		t.Fatal("expected error")
	}
}
