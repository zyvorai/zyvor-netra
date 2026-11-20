// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package bpfattachdiag

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var now = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func prog(name string) models.BPFProgram {
	owner := models.BPFOwnerOther
	switch {
	case strings.HasPrefix(name, "netra_"):
		owner = models.BPFOwnerNetra
	case strings.HasPrefix(name, "cil_"):
		owner = models.BPFOwnerCilium
	}
	return models.BPFProgram{ID: uint32(len(name)), Name: name, Owner: owner}
}

// agent builds a status whose hooks and interfaces are what the agent believes.
func agent(node string, hooks []string, ifs []string, inv *models.BPFAttachReport) models.AgentStatus {
	return models.AgentStatus{AgentReport: models.AgentReport{Node: node, Hooks: hooks, Interfaces: ifs, BPFAttach: inv}}
}

func inventory(ifaces ...models.BPFInterfaceAttach) *models.BPFAttachReport {
	return &models.BPFAttachReport{Available: true, TCXSupported: true, ObservedAt: now, Interfaces: ifaces, Total: len(ifaces)}
}

func eth0(in, eg []models.BPFProgram) models.BPFInterfaceAttach {
	return models.BPFInterfaceAttach{Name: "eth0", Index: 2, TCXIngress: in, TCXEgress: eg}
}

func kinds(r models.BPFAttachFindingsResponse) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Severity+":"+f.Kind)
	}
	return out
}

func TestAttachedHooksProduceNoFindings(t *testing.T) {
	a := agent("n1", []string{"tcx-ingress:eth0", "tcx-egress:eth0", "cgroup-egress", "tracepoint:skb/kfree_skb"}, []string{"eth0"},
		inventory(eth0([]models.BPFProgram{prog("cil_from_netdev"), prog("netra_ingress")}, []models.BPFProgram{prog("netra_egress")})))
	if r := Build([]models.AgentStatus{a}, now); len(r.Findings) != 0 || r.Evaluated != 1 {
		t.Fatalf("findings=%v", kinds(r))
	}
}

func TestHookLostWhenTheInterfaceWasRecreatedIsAWarning(t *testing.T) {
	// The agent still lists its hooks; the recreated eth0 has none of Netra's.
	a := agent("n1", []string{"tcx-ingress:eth0", "tcx-egress:eth0"}, []string{"eth0"},
		inventory(eth0([]models.BPFProgram{prog("cil_from_netdev")}, nil)))
	r := Build([]models.AgentStatus{a}, now)
	if got := kinds(r); len(got) != 1 || got[0] != "warning:"+KindHookMissing {
		t.Fatalf("findings=%v", got)
	}
	f := r.Findings[0]
	if !strings.Contains(f.Message, "tcx-ingress on eth0") || !strings.Contains(f.Message, "tcx-egress on eth0") || f.Value != 2 || f.Subject != "n1" {
		t.Fatalf("finding=%+v", f)
	}
	if len(f.Interfaces) != 1 || f.Interfaces[0] != "eth0" {
		t.Fatalf("interfaces=%v", f.Interfaces)
	}
}

func TestInterfaceGoneFromTheInventoryIsAlsoMissing(t *testing.T) {
	a := agent("n1", []string{"tcx-ingress:bond0"}, []string{"bond0"}, inventory())
	if got := kinds(Build([]models.AgentStatus{a}, now)); len(got) != 1 || got[0] != "warning:"+KindHookMissing {
		t.Fatalf("findings=%v", got)
	}
}

func TestLongProgramNamesMatchInFullOrTruncatedForm(t *testing.T) {
	hooks := []string{"edge-tcx-ingress:eth0", "capture-tcx-ingress:eth0"}
	// The kernel reports the full name when it has BTF function info (real kernels
	// on x86_64 and arm64 did), and 15 characters otherwise: both are the program.
	for name, progs := range map[string][]models.BPFProgram{
		"truncated": {prog("netra_edge_ingr"), prog("netra_capture_i")},
		"full":      {prog("netra_edge_ingress"), prog("netra_capture_ingress")},
	} {
		a := agent("n1", hooks, []string{"eth0"}, inventory(eth0(progs, nil)))
		if r := Build([]models.AgentStatus{a}, now); len(r.Findings) != 0 {
			t.Fatalf("%s names must match: %v", name, kinds(r))
		}
	}
}

func TestAnotherPrograms_NameDoesNotSatisfyTheHook(t *testing.T) {
	// A foreign program in the same slot is not Netra's.
	a := agent("n1", []string{"tcx-ingress:eth0"}, []string{"eth0"}, inventory(eth0([]models.BPFProgram{prog("other_ingress")}, nil)))
	if got := kinds(Build([]models.AgentStatus{a}, now)); len(got) != 1 || got[0] != "warning:"+KindHookMissing {
		t.Fatalf("findings=%v", got)
	}
}

func TestXDPMissingAndXDPReplaced(t *testing.T) {
	hooks := []string{"xdp:eth0"}
	xdp := func(p models.BPFProgram) models.BPFInterfaceAttach {
		p.Mode = "native"
		return models.BPFInterfaceAttach{Name: "eth0", Index: 2, XDP: &p}
	}
	if r := Build([]models.AgentStatus{agent("n1", hooks, []string{"eth0"}, inventory(xdp(prog("netra_xdp_ingre"))))}, now); len(r.Findings) != 0 {
		t.Fatalf("attached xdp: %v", kinds(r))
	}
	r := Build([]models.AgentStatus{agent("n1", hooks, []string{"eth0"}, inventory(xdp(prog("cil_xdp_entry"))))}, now)
	if got := kinds(r); len(got) != 1 || got[0] != "warning:"+KindXDPReplaced || !strings.Contains(r.Findings[0].Message, "cil_xdp_entry (cilium)") {
		t.Fatalf("replaced: %v %+v", got, r.Findings)
	}
	gone := models.BPFInterfaceAttach{Name: "eth0", Index: 2, TCXIngress: []models.BPFProgram{prog("cil_from_netdev")}}
	if got := kinds(Build([]models.AgentStatus{agent("n1", hooks, []string{"eth0"}, inventory(gone))}, now)); len(got) != 1 || got[0] != "warning:"+KindHookMissing {
		t.Fatalf("xdp detached: %v", got)
	}
}

func TestNeverGuessesWhenTheKernelCouldNotBeRead(t *testing.T) {
	hooks := []string{"tcx-ingress:eth0"}
	// Old kernel: TCX cannot be listed, so absence proves nothing.
	inv := inventory()
	inv.TCXSupported = false
	if r := Build([]models.AgentStatus{agent("n1", hooks, []string{"eth0"}, inv)}, now); len(r.Findings) != 0 {
		t.Fatalf("no-TCX kernel: %v", kinds(r))
	}
	// The query for this very interface failed: unknown, not detached.
	inv = inventory()
	inv.Failed = []string{"eth0"}
	if r := Build([]models.AgentStatus{agent("n1", hooks, []string{"eth0"}, inv)}, now); len(r.Findings) != 0 {
		t.Fatalf("unreadable interface: %v", kinds(r))
	}
	// The list was capped, so an unlisted interface may just be past the cap.
	inv = inventory()
	inv.Truncated = 40
	if r := Build([]models.AgentStatus{agent("n1", hooks, []string{"eth0"}, inv)}, now); len(r.Findings) != 0 {
		t.Fatalf("truncated inventory: %v", kinds(r))
	}
	// An unchanged stub the controller could not restore has no list to judge by.
	inv = &models.BPFAttachReport{Available: true, TCXSupported: true, ObservedAt: now, Unchanged: true}
	if r := Build([]models.AgentStatus{agent("n1", hooks, []string{"eth0"}, inv)}, now); len(r.Findings) != 0 {
		t.Fatalf("unrestorable stub: %v", kinds(r))
	}
}

func TestStaleInventoryIsSaidNotJudged(t *testing.T) {
	inv := inventory()
	inv.ObservedAt = now.Add(-10 * time.Minute)
	got := kinds(Build([]models.AgentStatus{agent("n1", []string{"tcx-ingress:eth0"}, []string{"eth0"}, inv)}, now))
	if len(got) != 1 || got[0] != "info:"+KindInventoryGap {
		t.Fatalf("findings=%v", got)
	}
}

func TestNoInterfaceHooksIsAnInfoNotAFault(t *testing.T) {
	// Only cgroup and tracepoint hooks: a configuration (agent.interfaces unset), not a failure.
	a := agent("n1", []string{"cgroup-egress", "raw-tracepoint:kfree_skb"}, nil, inventory())
	r := Build([]models.AgentStatus{a}, now)
	if got := kinds(r); len(got) != 1 || got[0] != "info:"+KindNoCoverage || !strings.Contains(r.Findings[0].Message, "agent.interfaces") {
		t.Fatalf("findings=%v", got)
	}
}

func TestSilenceIsCountedNotReadAsHealth(t *testing.T) {
	stale := agent("stale", []string{"tcx-ingress:eth0"}, []string{"eth0"}, inventory())
	stale.Stale = true
	off := agent("off", nil, nil, nil)
	blind := agent("blind", nil, nil, &models.BPFAttachReport{Unavailable: "list links: denied"})
	r := Build([]models.AgentStatus{stale, off, blind}, now)
	if len(r.Findings) != 0 || r.Evaluated != 0 || r.Skipped != 3 {
		t.Fatalf("evaluated=%d skipped=%d findings=%v", r.Evaluated, r.Skipped, kinds(r))
	}
}

func TestAnomaliesUseTheNodeAsSubjectAndValidSeverities(t *testing.T) {
	a := agent("n1", []string{"tcx-ingress:eth0"}, []string{"eth0"}, inventory())
	for _, an := range Anomalies(Build([]models.AgentStatus{a}, now).Findings) {
		if an.Subject != "n1" || an.SourceKey != "node:n1" || !strings.HasPrefix(an.Kind, "bpf-") {
			t.Fatalf("anomaly=%+v", an)
		}
		switch an.Severity {
		case "critical", "warning", "info":
		default:
			t.Fatalf("severity %q would fail closed in the notify filters", an.Severity)
		}
	}
}
