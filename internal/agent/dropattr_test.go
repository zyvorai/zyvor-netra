// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestAttributePolicyDrops(t *testing.T) {
	a := &Agent{}
	tcp := []models.TCPHealthStat{
		{Family: "IPv4", LocalIP: "10.0.0.5", LocalPort: 5000, RemoteIP: "10.0.0.9", RemotePort: 443, PID: 1234, Comm: "curl", Pod: "client-1"},
		{Family: "IPv4", LocalIP: "10.0.0.6", LocalPort: 5001, RemoteIP: "10.0.0.9", RemotePort: 443, PID: 0}, // no PID, never a match
	}
	drops := []models.PolicyDropStat{
		{Family: 4, Protocol: 6, Direction: 0, SrcAddr: "10.0.0.5", SrcPort: 5000, DstAddr: "10.0.0.9", DstPort: 443}, // egress TCP, matches
		{Family: 4, Protocol: 6, Direction: 1, SrcAddr: "10.0.0.9", SrcPort: 443, DstAddr: "10.0.0.5", DstPort: 5000}, // ingress
		{Family: 4, Protocol: 17, Direction: 0, SrcAddr: "10.0.0.5", SrcPort: 5000, DstAddr: "10.0.0.9", DstPort: 53}, // UDP
		{Family: 4, Protocol: 6, Direction: 0, SrcAddr: "10.0.0.7", SrcPort: 6000, DstAddr: "10.0.0.9", DstPort: 443}, // egress TCP, no match
	}

	out := a.attributePolicyDrops(drops, tcp)

	if out[0].AttributionState != "attributed" || out[0].PID != 1234 || out[0].Comm != "curl" || out[0].Pod != "client-1" {
		t.Errorf("expected drop 0 attributed to curl/1234, got %+v", out[0])
	}
	if out[1].AttributionState != "unattributable-ingress" || out[1].PID != 0 {
		t.Errorf("expected drop 1 unattributable-ingress, got %+v", out[1])
	}
	if out[2].AttributionState != "unattributable-protocol" || out[2].PID != 0 {
		t.Errorf("expected drop 2 unattributable-protocol, got %+v", out[2])
	}
	if out[3].AttributionState != "unmatched" || out[3].PID != 0 {
		t.Errorf("expected drop 3 unmatched, got %+v", out[3])
	}
}
