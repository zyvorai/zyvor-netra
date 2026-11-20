// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Peer is one remote Netra controller (read-only aggregator target).
type Peer struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	APIKey string `json:"-"`
	Tenant string `json:"tenant,omitempty"`
}

// ClusterSummary is one cluster's fleet inventory plus reachability.
type ClusterSummary struct {
	Name        string     `json:"name"`
	URL         string     `json:"url,omitempty"`
	Tenant      string     `json:"tenant,omitempty"`
	Local       bool       `json:"local,omitempty"`
	OK          bool       `json:"ok"`
	Error       string     `json:"error,omitempty"`
	AgentCount  int        `json:"agentCount,omitempty"`
	StaleAgents int        `json:"staleAgents,omitempty"`
	Workloads   int        `json:"workloads,omitempty"`
	FetchedAt   time.Time  `json:"fetchedAt,omitempty"`
	Inventory   *Inventory `json:"inventory,omitempty"`
}

// MultiCluster is GET /api/v1/fleet/clusters.
type MultiCluster struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Clusters    []ClusterSummary `json:"clusters"`
	PeerCount   int              `json:"peerCount"`
	Note        string           `json:"note"`
}

// TenantView is one partner/MSSP tenant rollup.
type TenantView struct {
	Tenant       string   `json:"tenant"`
	ClusterCount int      `json:"clusterCount"`
	OKClusters   int      `json:"okClusters"`
	AgentCount   int      `json:"agentCount"`
	Workloads    int      `json:"workloads"`
	StaleAgents  int      `json:"staleAgents,omitempty"`
	RiskScore    int      `json:"riskScore"` // 0-100 heuristic
	Risk         string   `json:"risk"`      // low|medium|high
	Clusters     []string `json:"clusters"`
}

// TenantRollup is GET /api/v1/fleet/tenants.
type TenantRollup struct {
	GeneratedAt time.Time    `json:"generatedAt"`
	Tenants     []TenantView `json:"tenants"`
	Count       int          `json:"count"`
	Untagged    int          `json:"untaggedClusters"`
	Note        string       `json:"note"`
}

// ParsePeers reads NETRA_FLEET_PEERS:
// "name|https://host|apikey" or "name|url|apikey|tenant" (tenant optional).
func ParsePeers(raw string) []Peer {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []Peer
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bits := strings.SplitN(part, "|", 4)
		if len(bits) < 2 {
			continue
		}
		p := Peer{Name: strings.TrimSpace(bits[0]), URL: strings.TrimRight(strings.TrimSpace(bits[1]), "/")}
		if len(bits) >= 3 {
			p.APIKey = strings.TrimSpace(bits[2])
		}
		if len(bits) >= 4 {
			p.Tenant = strings.TrimSpace(bits[3])
		}
		if p.Name == "" || p.URL == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Aggregate builds a multi-cluster view: local inventory plus best-effort
// remote GET /api/v1/fleet pulls. Never mutates remotes.
// localTenant is optional (NETRA_CLUSTER_TENANT).
func Aggregate(ctx context.Context, localName string, local Inventory, peers []Peer, client *http.Client) MultiCluster {
	return AggregateWithTenant(ctx, localName, "", local, peers, client)
}

// AggregateWithTenant is Aggregate plus an optional local tenant label.
func AggregateWithTenant(ctx context.Context, localName, localTenant string, local Inventory, peers []Peer, client *http.Client) MultiCluster {
	now := time.Now().UTC()
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	if localName == "" {
		localName = "local"
	}
	out := MultiCluster{
		GeneratedAt: now,
		Clusters: []ClusterSummary{{
			Name: localName, Tenant: strings.TrimSpace(localTenant), Local: true, OK: true,
			AgentCount: local.AgentCount, StaleAgents: local.StaleAgents,
			Workloads: local.Workloads, FetchedAt: now, Inventory: &local,
		}},
		PeerCount: len(peers),
		Note:      "Read-only aggregator. Remotes are polled best-effort; failures are reported per cluster. Optional peer tenant: name|url|key|tenant.",
	}
	for _, p := range peers {
		cs := fetchPeer(ctx, client, p)
		out.Clusters = append(out.Clusters, cs)
	}
	return out
}

// RollupTenants groups a MultiCluster by tenant label for MSSP/partner views.
func RollupTenants(mc MultiCluster) TenantRollup {
	type bucket struct {
		tv TenantView
	}
	by := map[string]*bucket{}
	untagged := 0
	for _, c := range mc.Clusters {
		t := strings.TrimSpace(c.Tenant)
		if t == "" {
			untagged++
			t = "_untagged"
		}
		b := by[t]
		if b == nil {
			label := t
			if t == "_untagged" {
				label = ""
			}
			b = &bucket{tv: TenantView{Tenant: label}}
			by[t] = b
		}
		b.tv.ClusterCount++
		if c.OK {
			b.tv.OKClusters++
		}
		b.tv.AgentCount += c.AgentCount
		b.tv.StaleAgents += c.StaleAgents
		b.tv.Workloads += c.Workloads
		b.tv.Clusters = append(b.tv.Clusters, c.Name)
	}
	out := TenantRollup{
		GeneratedAt: mc.GeneratedAt,
		Untagged:    untagged,
		Note:        "Partner/MSSP read-only tenant rollup from fleet cluster labels. RiskScore is a health heuristic (stale agents / unreachable), not threat intel.",
	}
	for _, b := range by {
		sort.Strings(b.tv.Clusters)
		b.tv.RiskScore, b.tv.Risk = tenantRisk(b.tv)
		out.Tenants = append(out.Tenants, b.tv)
	}
	sort.Slice(out.Tenants, func(i, j int) bool {
		if out.Tenants[i].Tenant == "" {
			return false
		}
		if out.Tenants[j].Tenant == "" {
			return true
		}
		return out.Tenants[i].Tenant < out.Tenants[j].Tenant
	})
	out.Count = len(out.Tenants)
	return out
}

func tenantRisk(tv TenantView) (int, string) {
	score := 0
	if tv.ClusterCount > 0 {
		bad := tv.ClusterCount - tv.OKClusters
		score += (bad * 40) / tv.ClusterCount
	}
	if tv.AgentCount > 0 {
		score += (tv.StaleAgents * 40) / tv.AgentCount
	}
	if tv.OKClusters == 0 && tv.ClusterCount > 0 {
		score += 30
	}
	if score > 100 {
		score = 100
	}
	switch {
	case score >= 50:
		return score, "high"
	case score >= 20:
		return score, "medium"
	default:
		return score, "low"
	}
}

func fetchPeer(ctx context.Context, client *http.Client, p Peer) ClusterSummary {
	cs := ClusterSummary{Name: p.Name, URL: p.URL, Tenant: p.Tenant, FetchedAt: time.Now().UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL+"/api/v1/fleet", nil)
	if err != nil {
		cs.Error = err.Error()
		return cs
	}
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		cs.Error = err.Error()
		return cs
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		cs.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
		return cs
	}
	var inv Inventory
	if err := json.Unmarshal(body, &inv); err != nil {
		cs.Error = "decode: " + err.Error()
		return cs
	}
	cs.OK = true
	cs.AgentCount = inv.AgentCount
	cs.StaleAgents = inv.StaleAgents
	cs.Workloads = inv.Workloads
	cs.Inventory = &inv
	return cs
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
