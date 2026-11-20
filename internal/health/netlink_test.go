// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package health

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func netlinkAgent(node string, events ...models.NetlinkEvent) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, Netlink: &models.NetlinkReport{Available: true, Epoch: 1, Events: events}}}
}

func pinNow(t *testing.T, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

func TestBuildCarriesNetlinkFindingsAsAnomalies(t *testing.T) {
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pinNow(t, at)
	a := netlinkAgent("worker-1", models.NetlinkEvent{
		Kind: "route", Action: "delete", Family: "ipv4", Destination: "default", Gateway: "10.0.0.1",
		Interface: "eth0", Table: 254, ObservedAt: at.Add(-2 * time.Minute), Sequence: 1, Epoch: 1,
	})
	resp := Build([]models.AgentStatus{a}, 20)
	var got *models.NetworkHealthAnomaly
	for i := range resp.Summary.Anomalies {
		if resp.Summary.Anomalies[i].Kind == "netlink-default-route-removed" {
			got = &resp.Summary.Anomalies[i]
		}
	}
	if got == nil {
		t.Fatalf("no netlink anomaly in %#v", resp.Summary.Anomalies)
	}
	if got.Severity != "critical" || got.Subject != "worker-1" || got.SourceKey != "node:worker-1" || !strings.Contains(got.Message, "10.0.0.1") {
		t.Fatalf("anomaly=%+v", got)
	}
}

func TestNetlinkFindingsDoNotMoveTheHealthScore(t *testing.T) {
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pinNow(t, at)
	quiet := Build([]models.AgentStatus{netlinkAgent("n")}, 20).Summary.HealthScore
	loud := Build([]models.AgentStatus{netlinkAgent("n", models.NetlinkEvent{
		Kind: "route", Action: "delete", Family: "ipv4", Destination: "default", Table: 254, ObservedAt: at.Add(-time.Minute),
	})}, 20).Summary.HealthScore
	if quiet != loud {
		t.Fatalf("score moved from %d to %d: the score is counter-driven, netlink findings are alerts", quiet, loud)
	}
}

func TestTwoNetlinkKindsOnOneNodeCorrelate(t *testing.T) {
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	pinNow(t, at)
	a := netlinkAgent("worker-1",
		models.NetlinkEvent{Kind: "route", Action: "delete", Family: "ipv4", Destination: "default", Table: 254, ObservedAt: at.Add(-time.Minute), Epoch: 1, Sequence: 1},
		models.NetlinkEvent{Kind: "overrun", Action: "lost", Detail: "route: no buffer space available", ObservedAt: at.Add(-time.Minute), Epoch: 1, Sequence: 2},
	)
	var correlated *models.NetworkHealthAnomaly
	for _, an := range Build([]models.AgentStatus{a}, 20).Summary.Anomalies {
		if an.Kind == "correlated-degradation" && an.Subject == "worker-1" {
			an := an
			correlated = &an
		}
	}
	if correlated == nil || correlated.Severity != "critical" || len(correlated.RelatedKinds) != 2 {
		t.Fatalf("correlated=%+v", correlated)
	}
}

func TestNodesWithoutTheRecorderAddNothing(t *testing.T) {
	pinNow(t, time.Now())
	resp := Build([]models.AgentStatus{{AgentReport: models.AgentReport{Node: "old-agent"}}}, 20)
	for _, an := range resp.Summary.Anomalies {
		if strings.HasPrefix(an.Kind, "netlink-") {
			t.Fatalf("unexpected %+v", an)
		}
	}
}

func TestBuildCarriesBPFAttachDriftAsAnAnomaly(t *testing.T) {
	pinNow(t, time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC))
	a := models.AgentStatus{AgentReport: models.AgentReport{
		Node: "worker-1", Hooks: []string{"tcx-ingress:eth0"}, Interfaces: []string{"eth0"},
		BPFAttach: &models.BPFAttachReport{Available: true, TCXSupported: true, ObservedAt: now()},
	}}
	var got *models.NetworkHealthAnomaly
	for _, an := range Build([]models.AgentStatus{a}, 20).Summary.Anomalies {
		if an.Kind == "bpf-netra-hook-missing" {
			an := an
			got = &an
		}
	}
	if got == nil || got.Severity != "warning" || got.Subject != "worker-1" || got.SourceKey != "node:worker-1" {
		t.Fatalf("anomaly=%+v", got)
	}
}
