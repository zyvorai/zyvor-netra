// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package identitydraft

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildSADraft(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Workloads: []models.WorkloadIdentity{{
				Namespace: "prod", Pod: "api-1", WorkloadKind: "Deployment", WorkloadName: "api",
				ServiceAccountName: "api-sa", Labels: map[string]string{"app": "api"}, CgroupID: 7,
			}},
			TLSMetadata: []models.TLSMetadataStat{{
				CgroupID: 7, SNI: "api.stripe.com", Handshakes: 2,
				Namespace: "prod", Pod: "api-1",
			}},
		},
	}}
	res := Build(agents, 10)
	if res.Count != 1 {
		t.Fatalf("%+v", res)
	}
	d := res.Drafts[0]
	if d.Kind != "allow_sni" || d.Namespace != "prod" {
		t.Fatalf("%+v", d)
	}
	sa, _ := d.Draft["serviceAccount"].(string)
	if sa != "api-sa" {
		t.Fatalf("sa=%v draft=%+v", sa, d.Draft)
	}
	m, _ := d.Draft["ciliumManifest"].(map[string]any)
	if m == nil || m["kind"] != "CiliumNetworkPolicy" {
		t.Fatalf("manifest %+v", m)
	}
}
