// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

// FlowCluster is one cluster's contribution to a fleet flow query.
type FlowCluster struct {
	Name        string           `json:"name"`
	Local       bool             `json:"local,omitempty"`
	OK          bool             `json:"ok"`
	Error       string           `json:"error,omitempty"`
	Matched     int              `json:"matched,omitempty"`
	Truncated   bool             `json:"truncated,omitempty"`
	Records     []flowlog.Record `json:"records,omitempty"`
	Limitations []string         `json:"limitations,omitempty"`
}

// FlowRollup is GET /api/v1/fleet/flows/history.
type FlowRollup struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Records     []flowlog.Record `json:"records"`
	Matched     int              `json:"matched"`
	Truncated   bool             `json:"truncated,omitempty"`
	Clusters    []FlowCluster    `json:"clusters"`
	Limitations []string         `json:"limitations"`
}

// AggregateFlows fans out a flow history query to peers and merges newest-first.
// Local records are tagged with Cluster via the Node field left unchanged;
// cluster name is only in the Clusters slice. Partial peer failures appear in
// Limitations and Clusters[].Error — never fail the whole rollup.
func AggregateFlows(ctx context.Context, localName string, local flowlog.Result, q flowlog.Query, peers []Peer, client *http.Client) FlowRollup {
	now := time.Now().UTC()
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	if localName == "" {
		localName = "local"
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	out := FlowRollup{
		GeneratedAt: now,
		Records:     append([]flowlog.Record(nil), local.Records...),
		Matched:     local.Matched,
		Truncated:   local.Truncated,
		Clusters: []FlowCluster{{
			Name: localName, Local: true, OK: true,
			Matched: local.Matched, Truncated: local.Truncated,
			Records: local.Records, Limitations: local.Limitations,
		}},
		Limitations: append([]string{
			"Fleet flow history fans out GET /api/v1/flows/history to NETRA_FLEET_PEERS and merges locally. Not a shared warehouse.",
		}, local.Limitations...),
	}
	for _, p := range peers {
		cl := FlowCluster{Name: p.Name}
		res, err := fetchPeerFlows(ctx, client, p, q)
		if err != nil {
			cl.Error = err.Error()
			out.Limitations = append(out.Limitations, fmt.Sprintf("peer %s: %v", p.Name, err))
			out.Clusters = append(out.Clusters, cl)
			continue
		}
		cl.OK = true
		cl.Matched = res.Matched
		cl.Truncated = res.Truncated
		cl.Limitations = res.Limitations
		cl.Records = res.Records
		out.Matched += res.Matched
		out.Truncated = out.Truncated || res.Truncated
		out.Records = append(out.Records, res.Records...)
		out.Clusters = append(out.Clusters, cl)
	}
	sort.SliceStable(out.Records, func(i, j int) bool {
		return out.Records[i].ObservedAt.After(out.Records[j].ObservedAt)
	})
	if len(out.Records) > limit {
		out.Records = out.Records[:limit]
		out.Truncated = true
	}
	return out
}

func fetchPeerFlows(ctx context.Context, client *http.Client, p Peer, q flowlog.Query) (flowlog.Result, error) {
	u, err := url.Parse(p.URL + "/api/v1/flows/history")
	if err != nil {
		return flowlog.Result{}, err
	}
	qv := u.Query()
	if !q.Since.IsZero() {
		qv.Set("since", q.Since.UTC().Format(time.RFC3339))
	}
	if q.Node != "" {
		qv.Set("node", q.Node)
	}
	if q.Namespace != "" {
		qv.Set("namespace", q.Namespace)
	}
	if q.Pod != "" {
		qv.Set("pod", q.Pod)
	}
	if q.Peer != "" {
		qv.Set("peer", q.Peer)
	}
	if q.Protocol != "" {
		qv.Set("protocol", q.Protocol)
	}
	if q.AppProtocol != "" {
		qv.Set("app", q.AppProtocol)
	}
	if q.Limit > 0 {
		qv.Set("limit", strconv.Itoa(q.Limit))
	}
	u.RawQuery = qv.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return flowlog.Result{}, err
	}
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return flowlog.Result{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return flowlog.Result{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return flowlog.Result{}, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var res flowlog.Result
	if err := json.Unmarshal(body, &res); err != nil {
		return flowlog.Result{}, err
	}
	return res, nil
}
