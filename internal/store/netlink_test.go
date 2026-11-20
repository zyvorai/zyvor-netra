// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func nlEvents(epoch int64, from, to uint64) []models.NetlinkEvent {
	var out []models.NetlinkEvent
	for seq := from; seq <= to; seq++ {
		out = append(out, models.NetlinkEvent{Epoch: epoch, Sequence: seq, Kind: models.NetlinkKindRoute, Action: "new"})
	}
	return out
}

func nlReport(node string, epoch int64, cursor uint64, snap *models.NetlinkSnapshot, events []models.NetlinkEvent) models.AgentReport {
	return models.AgentReport{
		Node: node, ObservedAt: time.Now().UTC(),
		Netlink: &models.NetlinkReport{Available: true, Epoch: epoch, Sequence: cursor, Cursor: cursor, Snapshot: snap, Events: events},
	}
}

func TestNetlinkHistoryAccumulatesAcrossReports(t *testing.T) {
	s := New()
	s.Report(nlReport("n1", 1, 3, nil, nlEvents(1, 1, 3)))
	s.Report(nlReport("n1", 1, 5, nil, nlEvents(1, 4, 5)))
	got := s.Agents()[0].Netlink
	if len(got.Events) != 5 || got.Events[0].Sequence != 1 || got.Events[4].Sequence != 5 {
		t.Fatalf("history not accumulated: %#v", got.Events)
	}
}

func TestNetlinkResentEventsAreNotDuplicated(t *testing.T) {
	s := New()
	s.Report(nlReport("n1", 1, 3, nil, nlEvents(1, 1, 3)))
	// The response was lost, so the agent resent 1-3 and added 4.
	s.Report(nlReport("n1", 1, 4, nil, nlEvents(1, 1, 4)))
	got := s.Agents()[0].Netlink
	if len(got.Events) != 4 {
		t.Fatalf("duplicates stored: %#v", got.Events)
	}
	for i, e := range got.Events {
		if e.Sequence != uint64(i+1) {
			t.Fatalf("order/dedupe wrong: %#v", got.Events)
		}
	}
}

func TestNetlinkAgentRestartKeepsOldHistoryAndStartsNewEpoch(t *testing.T) {
	s := New()
	s.Report(nlReport("n1", 1, 3, nil, nlEvents(1, 1, 3)))
	// The agent restarted: a new epoch whose sequence numbers begin again at 1.
	s.Report(nlReport("n1", 2, 2, nil, nlEvents(2, 1, 2)))
	got := s.Agents()[0].Netlink
	if len(got.Events) != 5 || got.Events[3].Epoch != 2 || got.Events[3].Sequence != 1 {
		t.Fatalf("restart must not be deduped against the old epoch: %#v", got.Events)
	}
}

func TestNetlinkSnapshotCarriesForwardWhenUnchanged(t *testing.T) {
	s := New()
	snap := &models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 1, Name: "lo"}}}
	s.Report(nlReport("n1", 1, 0, snap, nil))
	s.Report(nlReport("n1", 1, 0, nil, nil)) // unchanged: no snapshot in the report
	got := s.Agents()[0].Netlink
	if got.Snapshot == nil || len(got.Snapshot.Links) != 1 {
		t.Fatalf("snapshot lost on an unchanged report: %#v", got.Snapshot)
	}
	newer := &models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 1, Name: "lo"}, {Index: 2, Name: "eth0"}}}
	s.Report(nlReport("n1", 1, 0, newer, nil))
	if got := s.Agents()[0].Netlink; len(got.Snapshot.Links) != 2 {
		t.Fatalf("a changed snapshot must replace the old one: %#v", got.Snapshot)
	}
}

func TestNetlinkHistoryIsBounded(t *testing.T) {
	s := New()
	var cursor uint64
	for range 5 {
		s.Report(nlReport("n1", 1, cursor+500, nil, nlEvents(1, cursor+1, cursor+500)))
		cursor += 500
	}
	got := s.Agents()[0].Netlink
	if len(got.Events) != maxNetlinkEvents || got.Events[len(got.Events)-1].Sequence != 2500 {
		t.Fatalf("len=%d last=%d", len(got.Events), got.Events[len(got.Events)-1].Sequence)
	}
}

func TestNetlinkOffAndReadersCannotMutateStore(t *testing.T) {
	s := New()
	s.Report(models.AgentReport{Node: "off", ObservedAt: time.Now().UTC()})
	s.Report(nlReport("n1", 1, 1, nil, nlEvents(1, 1, 1)))
	for _, a := range s.Agents() {
		if a.Node == "off" && a.Netlink != nil {
			t.Fatal("a recorder that is off must stay nil")
		}
		if a.Node == "n1" {
			a.Netlink.Events[0].Kind = "mutated"
		}
	}
	for _, a := range s.AgentStatuses(time.Now(), time.Minute) {
		if a.Node == "n1" && a.Netlink.Events[0].Kind != models.NetlinkKindRoute {
			t.Fatal("a reader mutated the stored history")
		}
	}
}
