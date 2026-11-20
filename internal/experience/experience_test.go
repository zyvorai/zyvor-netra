// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package experience

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildDegradedWorkload(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			ConnectLatency: []models.ConnectLatencyStat{{
				Namespace: "prod", Pod: "api-1", WorkloadName: "api",
				Established: 10, TotalLatencyUS: 6_000_000, MaxLatencyUS: 900_000,
			}},
			TCPHealth: []models.TCPHealthStat{{
				Namespace: "prod", Pod: "api-1", WorkloadName: "api",
				Retransmissions: 200, RTOs: 30,
			}},
			DNSHealth: []models.DNSHealthStat{{
				Namespace: "prod", Pod: "api-1", WorkloadName: "api",
				Queries: 100, Failures: 40,
			}},
		},
	}}
	res := Build(agents, 50)
	if res.Count != 1 || res.Workloads[0].Score >= 60 {
		t.Fatalf("%+v", res)
	}
	if res.Degraded < 1 {
		t.Fatalf("expected degraded: %+v", res)
	}
}
