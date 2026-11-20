// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package dnsintel

import (
	"testing"

	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
)

func TestBuildIntelSuffix(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			DNSHealth: []models.DNSHealthStat{{
				Name: "evil.bad.example", Queries: 3, Namespace: "ns", Pod: "p",
			}},
		},
	}}
	res := Build(agents, []intel.Entry{{Type: "dns", Value: "bad.example"}}, 20)
	if res.Intel != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestLooksDGA(t *testing.T) {
	if !looksDGA("xqjvzrmtplkwnbhd.example.com") {
		t.Fatal("expected dga")
	}
	if looksDGA("api.github.com") {
		t.Fatal("github should not look dga")
	}
}
