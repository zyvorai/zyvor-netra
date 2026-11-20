// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bytes"
	"testing"
)

func TestFormatStatusReport(t *testing.T) {
	var buf bytes.Buffer
	formatStatusReport(&buf, &statusReport{
		Version:     "0.27.97",
		Datapath:    "standalone-ebpf",
		Mode:        "observe",
		Agents:      2,
		StaleAgents: 0,
		FeaturesOn:  3,
		FeaturesOff: 5,
		Summary:     "2 agents (0 stale)",
		Healthy:     true,
		Nodes: []statusNode{
			{Node: "node-a", Mode: "observe", Hooks: []string{"cgroup"}},
		},
	})
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("Netra status")) {
		t.Fatalf("missing header: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("node-a")) {
		t.Fatalf("missing node: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("Features:")) {
		t.Fatalf("missing features line: %s", out)
	}
}

func TestRedactHelmArgs(t *testing.T) {
	in := []string{"upgrade", "--set", "auth.apiKey=secret", "--set", "agent.enabled=true"}
	out := redactHelmArgs(in)
	if out[2] != "auth.apiKey=***" {
		t.Fatalf("expected redaction, got %v", out)
	}
	if out[4] != "agent.enabled=true" {
		t.Fatalf("non-secret set should stay: %v", out)
	}
}
