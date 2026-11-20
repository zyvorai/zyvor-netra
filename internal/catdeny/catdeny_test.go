// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package catdeny

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildSocial(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			TLSMetadata: []models.TLSMetadataStat{{SNI: "facebook.com", Handshakes: 2}},
		},
	}}
	res := Build(agents, nil, 20)
	if res.Count < 1 {
		t.Fatalf("%+v", res)
	}
}
