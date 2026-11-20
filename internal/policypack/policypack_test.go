// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package policypack

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildSanctionedPack(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			Workloads: []models.WorkloadIdentity{{
				Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api",
				Labels: map[string]string{"app": "api"}, CgroupID: 1,
			}},
			TLSMetadata: []models.TLSMetadataStat{{
				CgroupID: 1, SNI: "github.com", Handshakes: 3,
				Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api",
			}},
		},
	}}
	res := Build(agents, []string{"github.com"}, 10)
	if res.Count != 1 || len(res.Packs) != 1 {
		t.Fatalf("got %+v", res)
	}
	p := res.Packs[0]
	if p.Namespace != "prod" || p.Selector["app"] != "api" || len(p.FQDNs) != 1 || p.FQDNs[0] != "github.com" {
		t.Fatalf("%+v", p)
	}
	if p.Manifest["kind"] != "CiliumNetworkPolicy" {
		t.Fatalf("manifest %+v", p.Manifest)
	}
}

func TestBuildSkipsUnsanctioned(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Workloads: []models.WorkloadIdentity{{
				Namespace: "prod", Pod: "api-1", Labels: map[string]string{"app": "api"}, CgroupID: 1,
			}},
			TLSMetadata: []models.TLSMetadataStat{{
				CgroupID: 1, SNI: "evil.example", Namespace: "prod", Pod: "api-1",
			}},
		},
	}}
	res := Build(agents, []string{"github.com"}, 10)
	if res.Count != 0 {
		t.Fatalf("expected empty, got %+v", res)
	}
}
