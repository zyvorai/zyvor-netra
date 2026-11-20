// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package compliance

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildEmptyAgents(t *testing.T) {
	r := Build(nil, 50)
	if len(r.Packs) != 1 || r.Packs[0].ID != "network-hardening" {
		t.Fatalf("%+v", r)
	}
	if r.Packs[0].Passed+r.Packs[0].Failed+r.Packs[0].Warned == 0 {
		t.Fatal("expected controls evaluated")
	}
}

func TestBuildFailsOnBadRPFilter(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			SysctlNetworkAudit: models.SysctlAuditSnapshot{
				Entries: []models.SysctlAuditEntry{{
					Name: "net.ipv4.conf.eth0.rp_filter", Interface: "eth0",
					Category: "security", Value: "0", Source: "proc",
				}},
			},
		},
	}}
	r := Build(agents, 50)
	foundFail := false
	for _, c := range r.Packs[0].Controls {
		if c.ID == "net-rp-filter" && c.Status == "fail" {
			foundFail = true
		}
	}
	if !foundFail {
		t.Fatalf("%+v", r.Packs[0].Controls)
	}
}
