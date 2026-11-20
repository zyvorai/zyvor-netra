// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package store

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func bpfFull(hash string) *models.BPFAttachReport {
	return &models.BPFAttachReport{Available: true, TCXSupported: true, Hash: hash, Total: 1,
		Interfaces: []models.BPFInterfaceAttach{{Name: "eth0", Index: 2}}}
}

func bpfStub(hash string) *models.BPFAttachReport {
	return &models.BPFAttachReport{Available: true, TCXSupported: true, Hash: hash, Unchanged: true, Total: 1}
}

func reportBPF(node string, b *models.BPFAttachReport) models.AgentReport {
	return models.AgentReport{Node: node, ObservedAt: time.Now().UTC(), BPFAttach: b}
}

func TestBPFAttachUnchangedSummaryRestoresTheListWhenTheHashMatches(t *testing.T) {
	s := New()
	s.Report(reportBPF("n1", bpfFull("h1")))
	s.Report(reportBPF("n1", bpfStub("h1")))
	got := s.Agents()[0].BPFAttach
	if got.Unchanged || len(got.Interfaces) != 1 || got.Interfaces[0].Name != "eth0" {
		t.Fatalf("list not restored: %+v", got)
	}
}

func TestBPFAttachSummaryForAnUnknownListIsNeverInventedIntoOne(t *testing.T) {
	// The controller restarted: it never saw the full report for hash h1.
	s := New()
	s.Report(reportBPF("n1", bpfStub("h1")))
	got := s.Agents()[0].BPFAttach
	if !got.Unchanged || got.Interfaces != nil {
		t.Fatalf("a summary must not become an empty list: %+v", got)
	}
	// A different hash than the one held is not restored either.
	s.Report(reportBPF("n2", bpfFull("old")))
	s.Report(reportBPF("n2", bpfStub("new")))
	for _, a := range s.Agents() {
		if a.Node == "n2" && (!a.BPFAttach.Unchanged || a.BPFAttach.Interfaces != nil) {
			t.Fatalf("restored a list for a different hash: %+v", a.BPFAttach)
		}
	}
}

func TestBPFAttachOffStaysNilAndAChangedListReplaces(t *testing.T) {
	s := New()
	s.Report(models.AgentReport{Node: "off", ObservedAt: time.Now().UTC()})
	s.Report(reportBPF("n1", bpfFull("h1")))
	changed := bpfFull("h2")
	changed.Interfaces = []models.BPFInterfaceAttach{{Name: "eth1", Index: 3}}
	s.Report(reportBPF("n1", changed))
	for _, a := range s.AgentStatuses(time.Now(), time.Minute) {
		switch a.Node {
		case "off":
			if a.BPFAttach != nil {
				t.Fatal("an inventory that is off must stay nil")
			}
		case "n1":
			if len(a.BPFAttach.Interfaces) != 1 || a.BPFAttach.Interfaces[0].Name != "eth1" {
				t.Fatalf("changed list not stored: %+v", a.BPFAttach)
			}
			a.BPFAttach.Total = 99 // a reader mutating its copy must not reach the store
		}
	}
	for _, a := range s.Agents() {
		if a.Node == "n1" && a.BPFAttach.Total == 99 {
			t.Fatal("a reader mutated the stored report")
		}
	}
}
