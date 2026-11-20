// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package exfil

import (
	"fmt"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildFanOut(t *testing.T) {
	var stats []models.DestinationStat
	for i := 1; i <= 20; i++ {
		stats = append(stats, models.DestinationStat{
			Namespace: "prod", Pod: "api-1", WorkloadName: "api",
			DestinationIP: fmt.Sprintf("203.0.113.%d", i), Packets: 10000,
		})
	}
	agents := []models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", Stats: stats}}}
	res := Build(agents, 50)
	if res.Count != 1 || res.Findings[0].ExternalDsts < 15 {
		t.Fatalf("%+v", res)
	}
}
