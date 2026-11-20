// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package denysim

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestPreviewCIDRMatchesDestAndSkipsStale(t *testing.T) {
	agents := []models.AgentStatus{
		{
			AgentReport: models.AgentReport{
				Node: "n1",
				Stats: []models.DestinationStat{{
					DestinationIP: "10.0.0.8", Port: 443, Protocol: "TCP", Direction: "egress",
					Packets: 12, Bytes: 1200, Namespace: "prod", Pod: "api-a", WorkloadKind: "Deployment", WorkloadName: "api",
				}},
			},
		},
		{
			Stale: true,
			AgentReport: models.AgentReport{
				Node: "n2",
				Stats: []models.DestinationStat{{
					DestinationIP: "10.0.0.8", Port: 443, Protocol: "TCP", Direction: "egress", Packets: 99,
				}},
			},
		},
	}
	res, err := Preview(agents, Proposal{Kind: "cidr", Value: "10.0.0.0/24", Direction: "egress"})
	if err != nil {
		t.Fatal(err)
	}
	if res.AgentsSeen != 1 || res.AgentsStale != 1 {
		t.Fatalf("agents seen/stale = %d/%d", res.AgentsSeen, res.AgentsStale)
	}
	if res.HitCount != 1 || res.Hits[0].Packets != 12 {
		t.Fatalf("hits = %+v", res.Hits)
	}
	if res.Workloads != 1 || res.Hits[0].Source != "prod/Deployment/api" {
		t.Fatalf("source = %q", res.Hits[0].Source)
	}
	if res.Caveat == "" {
		t.Fatal("caveat missing")
	}
}

func TestPreviewExactIPAndPort(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			Stats: []models.DestinationStat{
				{DestinationIP: "1.1.1.1", Port: 53, Protocol: "UDP", Direction: "egress", Packets: 5},
				{DestinationIP: "1.1.1.1", Port: 443, Protocol: "TCP", Direction: "egress", Packets: 9},
			},
		},
	}}
	ip, err := Preview(agents, Proposal{Kind: "ip", Value: "1.1.1.1"})
	if err != nil || ip.HitCount != 2 {
		t.Fatalf("ip hits=%d err=%v", ip.HitCount, err)
	}
	port, err := Preview(agents, Proposal{Kind: "port", Value: "53", Protocol: "UDP"})
	if err != nil || port.HitCount != 1 || port.Hits[0].Packets != 5 {
		t.Fatalf("port = %+v err=%v", port, err)
	}
}

func TestPreviewDNSAndSNI(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			DNSHealth: []models.DNSHealthStat{{
				Name: "evil.example", Queries: 4, Namespace: "prod", Pod: "job", WorkloadName: "job",
			}},
			TLSMetadata: []models.TLSMetadataStat{{
				SNI: "cdn.example", Handshakes: 7, Namespace: "prod", Pod: "web", WorkloadName: "web",
			}},
		},
	}}
	dns, err := Preview(agents, Proposal{Kind: "dns", Value: "EVIL.EXAMPLE"})
	if err != nil || dns.HitCount != 1 || dns.Hits[0].Packets != 4 {
		t.Fatalf("dns = %+v err=%v", dns, err)
	}
	sni, err := Preview(agents, Proposal{Kind: "sni", Value: "cdn.example"})
	if err != nil || sni.HitCount != 1 || sni.Hits[0].Evidence != "tls-sni" {
		t.Fatalf("sni = %+v err=%v", sni, err)
	}
}

func TestPreviewRejectsBadKind(t *testing.T) {
	_, err := Preview(nil, Proposal{Kind: "magic", Value: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPreviewProcessUsesSampledEvents(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			Events: []models.FastPathEvent{
				{Comm: "curl", DestinationIP: "8.8.8.8", DestinationPort: 443, Protocol: "TCP", Direction: "egress", Length: 60},
				{Comm: "bash", DestinationIP: "1.1.1.1", DestinationPort: 53, Protocol: "UDP", Direction: "egress", Length: 40},
			},
		},
	}}
	res, err := Preview(agents, Proposal{Kind: "process", Value: "curl"})
	if err != nil || res.HitCount != 1 || res.Hits[0].Destination != "8.8.8.8:443" {
		t.Fatalf("got %+v err=%v", res, err)
	}
}
