// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package changeline

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func in() Inputs {
	return Inputs{Now: t0.Add(time.Hour), Since: t0.Add(-time.Hour), Lead: 10 * time.Minute}
}

func TestChangeThenBreakIsPaired(t *testing.T) {
	i := in()
	i.Netlink = []models.NetlinkEvent{
		{ObservedAt: t0, Node: "n1", Kind: "route", Action: "delete", Destination: "default", Interface: "eth0", Origin: "process", Actor: &models.NetlinkActor{Comm: "dhclient", PID: 42, Confidence: "probable"}},
		{ObservedAt: t0.Add(time.Minute), Node: "n2", Kind: "link", Action: "new", Interface: "eth1"},
	}
	i.Audit = []models.AuditEvent{{At: t0.Add(30 * time.Second), Actor: "alice", Action: "ebpf.mode", Target: "enforce"}}
	i.Alerts = []AlertChange{{At: t0.Add(2 * time.Minute), Rule: "rtt", Node: "n1", From: "clear", To: "critical", Info: "rtt high"}}
	r := Build(i)
	if len(r.Suspects) != 1 {
		t.Fatalf("suspects: %+v", r.Suspects)
	}
	s := r.Suspects[0]
	if !s.SameNode || s.Changes[0].Source != SourceNetlink || !strings.Contains(s.Changes[0].Summary, "dhclient") {
		t.Fatalf("same-node netlink change must rank first: %+v", s)
	}
	// n2's link change is on another node and must not be a suspect
	for _, c := range s.Changes {
		if c.Node == "n2" {
			t.Fatalf("other node leaked: %+v", c)
		}
	}
	if r.Counts[ClassBreak] != 1 || r.Counts[ClassChange] != 3 || r.Caveat == "" {
		t.Fatalf("counts %+v", r.Counts)
	}
}

func TestLeadWindowAndOrdering(t *testing.T) {
	i := in()
	i.Audit = []models.AuditEvent{{At: t0, Actor: "a", Action: "x"}}
	i.Alerts = []AlertChange{{At: t0.Add(30 * time.Minute), Rule: "r", Node: "n", To: "warning"}}
	if r := Build(i); len(r.Suspects) != 0 {
		t.Fatalf("change 30m before a 10m lead must not pair: %+v", r.Suspects)
	}
	i.Lead = time.Hour * 100
	r := Build(i)
	if r.Lead != maxLead.String() || len(r.Suspects) != 1 {
		t.Fatalf("lead clamp: %s %+v", r.Lead, r.Suspects)
	}
	for k := 1; k < len(r.Entries); k++ {
		if r.Entries[k-1].At.After(r.Entries[k].At) {
			t.Fatal("not ordered")
		}
	}
}

func TestLevelTriggeredStateIsNeverSuspectedAndSortsLast(t *testing.T) {
	i := in()
	i.Attach = []models.BPFAttachFinding{{Severity: "critical", Kind: "missing", Node: "n1", Subject: "eth0", Message: "hook gone"}}
	i.Drops = []models.DropDetectiveFinding{{Node: "n1", Confidence: "high", Code: "POLICY", Packets: 5000, Explanation: "policy deny"}}
	i.Audit = []models.AuditEvent{{At: t0, Actor: "a", Action: "x"}}
	r := Build(i)
	if len(r.Suspects) != 0 {
		t.Fatalf("untimed breaks must not pair: %+v", r.Suspects)
	}
	if r.Entries[0].Source != SourceAudit || r.Entries[1].AtKnown || r.Entries[2].AtKnown {
		t.Fatalf("order: %+v", r.Entries)
	}
}

func TestAnomalyBurstsMergeAndNodeFilter(t *testing.T) {
	i := in()
	for k := 0; k < 4; k++ {
		i.Anomaly = append(i.Anomaly, AnomalyPoint{Node: "n1", At: t0.Add(time.Duration(k) * time.Minute), Rate: 60})
	}
	i.Anomaly = append(i.Anomaly,
		AnomalyPoint{Node: "n1", At: t0.Add(30 * time.Minute), Rate: 25},
		AnomalyPoint{Node: "n1", At: t0.Add(40 * time.Minute), Rate: 5}, // below threshold
		AnomalyPoint{Node: "n2", At: t0, Rate: 90})
	r := Build(i)
	if r.Counts[ClassBreak] != 3 {
		t.Fatalf("want 2 bursts for n1 + 1 for n2: %+v", r.Entries)
	}
	i.Node = "n1"
	if r := Build(i); r.Counts[ClassBreak] != 2 {
		t.Fatalf("node filter: %+v", r.Entries)
	}
}

func TestOverrunBecomesGapNotChange(t *testing.T) {
	i := in()
	i.Netlink = []models.NetlinkEvent{{ObservedAt: t0, Node: "n1", Kind: "overrun", Detail: "ENOBUFS"}}
	i.Gaps = []string{"b gap", "b gap", "a gap"}
	r := Build(i)
	if len(r.Entries) != 0 || len(r.Gaps) != 3 || r.Gaps[0] != "a gap" {
		t.Fatalf("%+v %v", r.Entries, r.Gaps)
	}
}

func TestHostileInput(t *testing.T) {
	i := in()
	evil := strings.Repeat("A", 5000) + "\x1b[31m\nINJECT"
	i.Audit = []models.AuditEvent{
		{At: t0, Actor: evil, Action: evil, Target: evil},
		{At: time.Time{}, Actor: "zero", Action: "x"},            // zero time dropped
		{At: t0.Add(-48 * time.Hour), Actor: "old", Action: "x"}, // before since
		{At: t0.Add(48 * time.Hour), Actor: "future", Action: "x"},
	}
	i.Netlink = []models.NetlinkEvent{{ObservedAt: t0, Node: evil, Kind: "route", Action: "delete", Destination: evil}}
	r := Build(i)
	if len(r.Entries) != 2 {
		t.Fatalf("entries: %d", len(r.Entries))
	}
	for _, e := range r.Entries {
		if len(e.Summary) > 310 || strings.ContainsAny(e.Summary, "\n\x1b") {
			t.Fatalf("unsanitized summary: %q", e.Summary)
		}
	}
	// zero Inputs must not panic
	if r := Build(Inputs{}); r.Entries == nil || r.Suspects == nil || r.Gaps == nil {
		t.Fatal("nil slices in JSON output")
	}
}

func TestTruncationKeepsUntimedState(t *testing.T) {
	i := in()
	for k := 0; k < maxEntries+50; k++ {
		i.Audit = append(i.Audit, models.AuditEvent{At: t0.Add(time.Duration(k) * time.Second), Actor: "a", Action: "x"})
	}
	i.Attach = []models.BPFAttachFinding{{Severity: "warning", Kind: "k", Node: "n", Subject: "s", Message: "m"}}
	r := Build(i)
	if !r.Truncated || len(r.Entries) != maxEntries || r.Entries[len(r.Entries)-1].Source != SourceBPFAttach {
		t.Fatalf("trunc %v %d", r.Truncated, len(r.Entries))
	}
}
