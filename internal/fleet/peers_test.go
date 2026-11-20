// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParsePeers(t *testing.T) {
	p := ParsePeers("east|https://a.example|key1, west|https://b.example|key2|acme")
	if len(p) != 2 || p[0].Name != "east" || p[1].APIKey != "key2" || p[1].Tenant != "acme" {
		t.Fatalf("%+v", p)
	}
}

func TestRollupTenants(t *testing.T) {
	mc := MultiCluster{Clusters: []ClusterSummary{
		{Name: "a", Tenant: "acme", OK: true, AgentCount: 2, Workloads: 5},
		{Name: "b", Tenant: "acme", OK: true, AgentCount: 1, Workloads: 3},
		{Name: "c", OK: false, AgentCount: 0},
	}}
	r := RollupTenants(mc)
	if r.Count != 2 || r.Untagged != 1 {
		t.Fatalf("%+v", r)
	}
	var acme *TenantView
	for i := range r.Tenants {
		if r.Tenants[i].Tenant == "acme" {
			acme = &r.Tenants[i]
		}
	}
	if acme == nil || acme.ClusterCount != 2 || acme.AgentCount != 3 {
		t.Fatalf("%+v", r.Tenants)
	}
}

func TestAggregateLocalAndPeer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Inventory{GeneratedAt: time.Now().UTC(), AgentCount: 2, Workloads: 5})
	}))
	defer srv.Close()
	local := Inventory{AgentCount: 1, Workloads: 3}
	out := Aggregate(context.Background(), "home", local, []Peer{{Name: "peer", URL: srv.URL, APIKey: "k"}}, srv.Client())
	if len(out.Clusters) != 2 || !out.Clusters[0].Local || !out.Clusters[1].OK {
		t.Fatalf("%+v", out)
	}
}
