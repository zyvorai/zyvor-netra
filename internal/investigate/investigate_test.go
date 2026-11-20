// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package investigate

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/coverage"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
)

func TestComposeTimelineAndGaps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	res := Compose(Request{
		Namespace: "app", Pod: "api", Peer: "10.0.0.8", Port: 443,
		Since: now.Add(-10 * time.Minute), Until: now,
	}, Input{
		Now: now,
		Agents: []models.AgentStatus{{
			AgentReport: models.AgentReport{Node: "n1"},
			Stale:       false,
		}},
		FlowRecords: []flowlog.Record{{
			ObservedAt: now.Add(-time.Minute), Namespace: "app", Pod: "api",
			Peer: "10.0.0.8", Port: 443, Blocked: 3, Retrans: 2, Packets: 10,
		}},
		DNSRows:   []DNSRow{{Name: "db.svc", Failures: 2, Queries: 5}},
		Detective: []DetectiveHit{{Summary: "policy drop egress", Confidence: "exact", Namespace: "app", Pod: "api", Peer: "10.0.0.8"}},
		NetlinkEvents: []models.NetlinkEvent{{
			ObservedAt: now.Add(-2 * time.Minute), Node: "n1", Kind: "route", Action: "new", Destination: "10.0.0.0/8",
		}},
		PathNotes: []string{"high retrans on path"},
		DropNotes: []string{"kfree_skb reason TCP_INVALID"},
		Coverage: coverage.Matrix{Nodes: []coverage.Node{{
			Node: "n1", Programs: []coverage.Program{{Name: "netra_egress", Attached: true}},
		}}},
	})
	if len(res.Events) < 4 {
		t.Fatalf("events %d: %+v", len(res.Events), res.Events)
	}
	if res.Confidence.Overall == "" {
		t.Fatal("empty confidence")
	}
	var sawVisibility bool
	for _, g := range res.Gaps {
		if g.Stage == "visibility" {
			sawVisibility = true
		}
	}
	if !sawVisibility {
		t.Fatalf("gaps: %+v", res.Gaps)
	}
}

func TestComposeEmptyIsHonestGap(t *testing.T) {
	now := time.Now().UTC()
	res := Compose(Request{Namespace: "x"}, Input{Now: now})
	if len(res.Events) != 0 {
		t.Fatalf("events %+v", res.Events)
	}
	found := false
	for _, g := range res.Gaps {
		if g.Stage == "visibility" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected visibility gap")
	}
}
