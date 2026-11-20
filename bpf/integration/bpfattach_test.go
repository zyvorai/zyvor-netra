// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/zyvorai/netra/internal/bpfattach"
	"github.com/zyvorai/netra/internal/bpfattachdiag"
	"github.com/zyvorai/netra/internal/models"
)

// These attach Netra's real programs (the compiled object's netra_ingress,
// netra_egress and netra_xdp_ingress) to a scratch veth and ask the real kernel
// what is attached, through the same collector the agent runs. Nothing outside
// the scratch interface is touched, and nothing here modifies an attachment the
// test did not create.

func run(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// tinyProg is a program that returns 0 and does nothing else, standing in for
// somebody else's program on the same hook.
func tinyProg(t *testing.T, name string, typ ebpf.ProgramType) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: name, Type: typ, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func ifaceEntry(t *testing.T, rep models.BPFAttachReport, name string) models.BPFInterfaceAttach {
	t.Helper()
	for _, ia := range rep.Interfaces {
		if ia.Name == name {
			return ia
		}
	}
	t.Fatalf("%s is not in the inventory (interfaces=%d, error=%q)", name, len(rep.Interfaces), rep.Error)
	return models.BPFInterfaceAttach{}
}

func has(list []models.BPFProgram, program, owner string) bool {
	for _, p := range list {
		if p.Owner == owner && bpfattach.Same(program, p.Name) {
			return true
		}
	}
	return false
}

// scratchVeth creates nlbp0 <-> nlbp1 and removes it afterwards.
func scratchVeth(t *testing.T) {
	t.Helper()
	_ = exec.Command("ip", "link", "del", "nlbp0").Run()
	run(t, "link", "add", "nlbp0", "type", "veth", "peer", "name", "nlbp1")
	run(t, "link", "set", "nlbp0", "up")
	run(t, "link", "set", "nlbp1", "up")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "nlbp0").Run() })
}

func linkIndex(t *testing.T, name string) int {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return l.Attrs().Index
}

func TestBPFAttachInventoryReportsRealAttachments(t *testing.T) {
	coll := loadCollection(t)
	scratchVeth(t)
	idx := linkIndex(t, "nlbp0")

	// Somebody else's program goes in first; Netra's attaches after it.
	other := tinyProg(t, "other_probe", ebpf.SchedCLS)
	foreign, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: other, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		if errors.Is(err, link.ErrNotSupported) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skip("kernel has no TCX (before 6.6)")
		}
		t.Fatalf("attach foreign TCX: %v", err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	for _, h := range []struct {
		prog   string
		attach ebpf.AttachType
	}{{"netra_ingress", ebpf.AttachTCXIngress}, {"netra_egress", ebpf.AttachTCXEgress}} {
		l, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: mustProgram(t, coll, h.prog), Attach: h.attach})
		if err != nil {
			t.Fatalf("attach %s: %v", h.prog, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	xdp, err := link.AttachXDP(link.XDPOptions{Program: mustProgram(t, coll, "netra_xdp_ingress"), Interface: idx, Flags: link.XDPGenericMode})
	if err != nil {
		t.Fatalf("attach XDP: %v", err)
	}
	t.Cleanup(func() { _ = xdp.Close() })

	// A classic cls_bpf filter on the peer, the mechanism netlink (not bpf_link) attaches.
	idx1 := linkIndex(t, "nlbp1")
	if err := netlink.QdiscAdd(&netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: idx1, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT},
		QdiscType:  "clsact",
	}); err != nil {
		t.Fatalf("add clsact: %v", err)
	}
	legacy := tinyProg(t, "legacy_cls", ebpf.SchedCLS)
	if err := netlink.FilterAdd(&netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{LinkIndex: idx1, Parent: netlink.HANDLE_MIN_INGRESS, Handle: 1, Protocol: unix.ETH_P_ALL, Priority: 1},
		Fd:          legacy.FD(), Name: "legacy_cls", DirectAction: true,
	}); err != nil {
		t.Fatalf("add cls_bpf filter: %v", err)
	}

	rep := bpfattach.Collect(bpfattach.NewSource(), time.Now())
	if !rep.Available || !rep.TCXSupported {
		t.Fatalf("report=%+v", rep)
	}
	for _, f := range rep.Failed {
		if f == "nlbp0" || f == "nlbp1" {
			t.Fatalf("the scratch interface %s could not be read: %s", f, rep.Error)
		}
	}
	eth := ifaceEntry(t, rep, "nlbp0")
	// Execution order is the kernel's: the foreign program was attached first, so it runs first.
	if len(eth.TCXIngress) != 2 || eth.TCXIngress[0].Owner != models.BPFOwnerOther || eth.TCXIngress[0].Name != "other_probe" ||
		!has(eth.TCXIngress, "netra_ingress", models.BPFOwnerNetra) {
		t.Fatalf("tcx ingress=%+v", eth.TCXIngress)
	}
	if !has(eth.TCXEgress, "netra_egress", models.BPFOwnerNetra) {
		t.Fatalf("tcx egress=%+v", eth.TCXEgress)
	}
	if eth.XDP == nil || eth.XDP.Mode != "generic" || !bpfattach.Same("netra_xdp_ingress", eth.XDP.Name) || eth.XDP.Owner != models.BPFOwnerNetra {
		t.Fatalf("xdp=%+v", eth.XDP)
	}
	peerEntry := ifaceEntry(t, rep, "nlbp1")
	if len(peerEntry.TCIngress) != 1 || peerEntry.TCIngress[0].Name != "legacy_cls" || peerEntry.TCIngress[0].Owner != models.BPFOwnerOther {
		t.Fatalf("classic tc=%+v", peerEntry.TCIngress)
	}
	if rep.Hash == "" || rep.Hash != bpfattach.Hash(rep) {
		t.Fatalf("hash=%q", rep.Hash)
	}

	// What the agent believes matches the kernel: no findings.
	agent := models.AgentStatus{AgentReport: models.AgentReport{
		Node: "ci", Interfaces: []string{"nlbp0"},
		Hooks:     []string{"tcx-ingress:nlbp0", "tcx-egress:nlbp0", "xdp:nlbp0"},
		BPFAttach: &rep,
	}}
	if r := bpfattachdiag.Build([]models.AgentStatus{agent}, time.Now()); len(r.Findings) != 0 {
		t.Fatalf("attached hooks reported as drift: %+v", r.Findings)
	}
}

// The reason the inventory exists: Netra's hook disappears and the agent's own
// hook list still says it is attached.
func TestBPFAttachDriftIsSeenWhenAHookIsDetachedOrTheInterfaceRecreated(t *testing.T) {
	coll := loadCollection(t)
	scratchVeth(t)
	idx := linkIndex(t, "nlbp0")
	ingress, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: mustProgram(t, coll, "netra_ingress"), Attach: ebpf.AttachTCXIngress})
	if err != nil {
		if errors.Is(err, link.ErrNotSupported) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skip("kernel has no TCX (before 6.6)")
		}
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(func() { _ = ingress.Close() })
	egress, err := link.AttachTCX(link.TCXOptions{Interface: idx, Program: mustProgram(t, coll, "netra_egress"), Attach: ebpf.AttachTCXEgress})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(func() { _ = egress.Close() })

	believes := models.AgentReport{Node: "ci", Interfaces: []string{"nlbp0"}, Hooks: []string{"tcx-ingress:nlbp0", "tcx-egress:nlbp0"}}
	judge := func() []models.BPFAttachFinding {
		rep := bpfattach.Collect(bpfattach.NewSource(), time.Now())
		a := models.AgentStatus{AgentReport: believes}
		a.BPFAttach = &rep
		return bpfattachdiag.Build([]models.AgentStatus{a}, time.Now()).Findings
	}
	if f := judge(); len(f) != 0 {
		t.Fatalf("healthy hooks reported as drift: %+v", f)
	}

	// 1. A privileged detach of the ingress hook.
	if err := ingress.Close(); err != nil {
		t.Fatal(err)
	}
	f := judge()
	if len(f) != 1 || f[0].Kind != bpfattachdiag.KindHookMissing || !strings.Contains(f[0].Message, "tcx-ingress on nlbp0") ||
		strings.Contains(f[0].Message, "tcx-egress") {
		t.Fatalf("a detached ingress hook must be reported alone: %+v", f)
	}

	// 2. The interface is deleted and recreated under the same name: a bpf_link
	// dies with its device, so both hooks are gone, and only the kernel knows.
	run(t, "link", "del", "nlbp0")
	run(t, "link", "add", "nlbp0", "type", "veth", "peer", "name", "nlbp1")
	run(t, "link", "set", "nlbp0", "up")
	f = judge()
	if len(f) != 1 || f[0].Kind != bpfattachdiag.KindHookMissing || !strings.Contains(f[0].Message, "tcx-egress on nlbp0") {
		t.Fatalf("a recreated interface must be reported as having lost its hooks: %+v", f)
	}
}
