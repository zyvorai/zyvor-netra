// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package shadowsaas

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestShadowUnsanctionedSaaS(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			TLSMetadata: []models.TLSMetadataStat{
				{SNI: "login.salesforce.com", Handshakes: 5, Namespace: "ns", Pod: "p"},
				{SNI: "login.microsoftonline.com", Handshakes: 2}, // may be unknown
				{SNI: "api.openai.com", Handshakes: 3},
			},
		},
	}}
	res := Build(agents, []string{"microsoft.com", "office.com"}, 50)
	if res.Shadow < 1 {
		t.Fatalf("expected shadow findings: %+v", res)
	}
	var sawSF, sawAI bool
	for _, f := range res.Findings {
		if f.Host == "login.salesforce.com" && f.Status == "shadow" {
			sawSF = true
		}
		if f.Host == "api.openai.com" && f.AIRelated {
			sawAI = true
		}
	}
	if !sawSF || !sawAI {
		t.Fatalf("sf=%v ai=%v findings=%+v", sawSF, sawAI, res.Findings)
	}
}

func TestParseSanctioned(t *testing.T) {
	got := ParseSanctioned("a.com, b.org;c.net")
	if len(got) != 3 {
		t.Fatalf("%v", got)
	}
}
