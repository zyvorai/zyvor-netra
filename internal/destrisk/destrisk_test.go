// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package destrisk

import (
	"testing"

	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
)

func TestBuildRanksAIAndIntel(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			TLSMetadata: []models.TLSMetadataStat{{SNI: "api.openai.com", Handshakes: 9}},
			Stats: []models.DestinationStat{{
				DestinationIP: "203.0.113.50", Packets: 50000, Protocol: "TCP",
			}},
		},
	}}
	feed := []intel.Entry{{Type: "ip", Value: "203.0.113.50", Direction: "egress"}}
	res := Build(agents, feed, 50)
	if res.Count < 1 {
		t.Fatalf("%+v", res)
	}
	top := res.Destinations[0]
	if top.Score < 20 {
		t.Fatalf("expected elevated score: %+v", top)
	}
}
