// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MetricAlertRef is one raised metric alert in a cluster summary.
type MetricAlertRef struct {
	Rule   string `json:"rule"`
	Status string `json:"status"`
	Node   string `json:"node"`
	Chart  string `json:"chart"`
}

// MetricRef is one anomalous dimension in a cluster summary.
type MetricRef struct {
	Node        string  `json:"node"`
	Chart       string  `json:"chart"`
	Dimension   string  `json:"dimension"`
	AnomalyRate float64 `json:"anomalyRate"`
}

// MetricsSummary is one cluster's metrics platform at a glance:
// GET /api/v1/metrics/summary.
type MetricsSummary struct {
	Available      bool             `json:"available"`
	Nodes          int              `json:"nodes"`
	StaleNodes     int              `json:"staleNodes"`
	Series         int              `json:"series"`
	AnomalyRate    float64          `json:"anomalyRate"` // percent of samples flagged, last 15m
	AlertsCritical int              `json:"alertsCritical"`
	AlertsWarning  int              `json:"alertsWarning"`
	TopAlerts      []MetricAlertRef `json:"topAlerts"`
	TopAnomalous   []MetricRef      `json:"topAnomalous"`
}

// ClusterMetrics is one cluster in the fleet metrics roll-up.
type ClusterMetrics struct {
	Name      string          `json:"name"`
	URL       string          `json:"url,omitempty"`
	Tenant    string          `json:"tenant,omitempty"`
	Local     bool            `json:"local,omitempty"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	FetchedAt time.Time       `json:"fetchedAt"`
	Summary   *MetricsSummary `json:"summary,omitempty"`
}

// MetricsTotals sums every reachable cluster; AnomalyRate is weighted by
// each cluster's node count.
type MetricsTotals struct {
	Clusters       int     `json:"clusters"`
	OKClusters     int     `json:"okClusters"`
	Nodes          int     `json:"nodes"`
	Series         int     `json:"series"`
	AnomalyRate    float64 `json:"anomalyRate"`
	AlertsCritical int     `json:"alertsCritical"`
	AlertsWarning  int     `json:"alertsWarning"`
}

// MetricsRollup is GET /api/v1/metrics/fleet.
type MetricsRollup struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Clusters    []ClusterMetrics `json:"clusters"`
	Totals      MetricsTotals    `json:"totals"`
	Note        string           `json:"note"`
}

// AggregateMetrics combines the local summary with each peer's
// GET /api/v1/metrics/summary, fetched in parallel. Read-only: remotes are
// only ever read, and a peer's own peers are not followed.
func AggregateMetrics(ctx context.Context, localName, localTenant string, local MetricsSummary, peers []Peer, client *http.Client) MetricsRollup {
	now := time.Now().UTC()
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	if localName == "" {
		localName = "local"
	}
	out := MetricsRollup{
		GeneratedAt: now,
		Clusters:    make([]ClusterMetrics, 1+len(peers)),
		Note:        "Read-only roll-up of each cluster's metrics summary. Peers are polled best-effort in parallel; their own peers are not followed.",
	}
	out.Clusters[0] = ClusterMetrics{Name: localName, Tenant: strings.TrimSpace(localTenant), Local: true, OK: true, FetchedAt: now, Summary: &local}
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func(i int, p Peer) {
			defer wg.Done()
			out.Clusters[i+1] = fetchPeerMetrics(ctx, client, p)
		}(i, p)
	}
	wg.Wait()
	var weighted float64
	for _, c := range out.Clusters {
		out.Totals.Clusters++
		if !c.OK || c.Summary == nil {
			continue
		}
		out.Totals.OKClusters++
		s := c.Summary
		out.Totals.Nodes += s.Nodes
		out.Totals.Series += s.Series
		out.Totals.AlertsCritical += s.AlertsCritical
		out.Totals.AlertsWarning += s.AlertsWarning
		weighted += s.AnomalyRate * float64(s.Nodes)
	}
	if out.Totals.Nodes > 0 {
		out.Totals.AnomalyRate = weighted / float64(out.Totals.Nodes)
	}
	return out
}

func fetchPeerMetrics(ctx context.Context, client *http.Client, p Peer) ClusterMetrics {
	cm := ClusterMetrics{Name: p.Name, URL: p.URL, Tenant: p.Tenant, FetchedAt: time.Now().UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL+"/api/v1/metrics/summary", nil)
	if err != nil {
		cm.Error = err.Error()
		return cm
	}
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		cm.Error = err.Error()
		return cm
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		cm.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
		return cm
	}
	var s MetricsSummary
	if err := json.Unmarshal(body, &s); err != nil {
		cm.Error = "decode: " + err.Error()
		return cm
	}
	cm.OK, cm.Summary = true, &s
	return cm
}
