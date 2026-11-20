// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package echblind

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/tlsfp"
)

func TestBuildMissingSNI(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			ConnectionAttempts: []models.ConnectionAttemptStat{{
				Namespace: "prod", Pod: "api-1", RemoteIP: "1.2.3.4", RemotePort: 443, Attempts: 9,
			}},
		},
	}}
	res := Build(agents, nil, 50)
	if res.MissingSNI != 1 || res.Count < 1 {
		t.Fatalf("%+v", res)
	}
}

func TestBuildECHHello(t *testing.T) {
	res := Build(nil, []tlsfp.Observation{{
		Fingerprint: tlsfp.Fingerprint{JA3: "abc", ECH: true, SNI: ""},
		Count:       2,
	}}, 10)
	if res.ECHHello != 1 {
		t.Fatalf("%+v", res)
	}
}
