// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package ipv6diag

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestBuildAggregatesAcrossNodes(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", IPv6ExtHeaders: []models.IPv6ExtHeaderStat{
		{Direction: "egress", Hook: "cgroup", Packets: 100, ExtHeaderPackets: 10, TotalExtHeaders: 12, Fragmented: 5},
	}}}}, 10)
	if r.Summary.Packets != 100 || r.Summary.ExtHeaderPackets != 10 || r.Summary.Fragmented != 5 {
		t.Fatalf("unexpected summary: %#v", r.Summary)
	}
	if len(r.Nodes) != 1 || r.Nodes[0].Node != "n1" {
		t.Fatalf("unexpected nodes: %#v", r.Nodes)
	}
}

func TestBuildSkipsStale(t *testing.T) {
	r := Build([]models.AgentStatus{{Stale: true, AgentReport: models.AgentReport{Node: "n1", IPv6ExtHeaders: []models.IPv6ExtHeaderStat{{Packets: 999}}}}}, 10)
	if r.Summary.Packets != 0 || len(r.Nodes) != 0 {
		t.Fatalf("stale agent included: %#v", r)
	}
}

func TestHighFragmentationRateAnomaly(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", IPv6ExtHeaders: []models.IPv6ExtHeaderStat{
		{Direction: "egress", Hook: "cgroup", Packets: 2000, Fragmented: 200}, // 10% fragmentation, above the 5% floor
	}}}}, 10)
	found := false
	for _, a := range r.Summary.Anomalies {
		if a.Kind == "high-fragmentation-rate" {
			found = true
			if a.Severity != "warning" {
				t.Fatalf("expected warning severity at 10%% fragmentation, got %s", a.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected high-fragmentation-rate anomaly, got %+v", r.Summary.Anomalies)
	}
}

func TestFragmentationBelowMinSampleIsSuppressed(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", IPv6ExtHeaders: []models.IPv6ExtHeaderStat{
		{Direction: "egress", Hook: "cgroup", Packets: 10, Fragmented: 10}, // 100% fragmented, but tiny sample
	}}}}, 10)
	for _, a := range r.Summary.Anomalies {
		if a.Kind == "high-fragmentation-rate" {
			t.Fatalf("expected fragmentation anomaly to be suppressed below minFragmentationSample, got %+v", a)
		}
	}
}

func TestChainTruncatedAnomaly(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", IPv6ExtHeaders: []models.IPv6ExtHeaderStat{
		{Direction: "egress", Hook: "cgroup", Packets: 50, ChainTruncated: 150},
	}}}}, 10)
	found := false
	for _, a := range r.Summary.Anomalies {
		if a.Kind == "ext-chain-frequently-truncated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ext-chain-frequently-truncated anomaly, got %+v", r.Summary.Anomalies)
	}
}

func TestTopNTruncatesPerNode(t *testing.T) {
	r := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "n1", IPv6ExtHeaders: []models.IPv6ExtHeaderStat{
		{Direction: "egress", Hook: "cgroup", Packets: 5},
		{Direction: "ingress", Hook: "cgroup", Packets: 50},
		{Direction: "egress", Hook: "xdp", Packets: 500},
	}}}}, 2)
	if len(r.Nodes[0].ExtHeaders) != 2 {
		t.Fatalf("expected topN=2 truncation, got %d rows", len(r.Nodes[0].ExtHeaders))
	}
	if r.Nodes[0].ExtHeaders[0].Packets != 500 || r.Nodes[0].ExtHeaders[1].Packets != 50 {
		t.Fatalf("expected rows sorted by packets desc, got %+v", r.Nodes[0].ExtHeaders)
	}
}
