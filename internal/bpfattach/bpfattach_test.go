// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package bpfattach

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type fakeKernel struct {
	links     []LinkInfo
	tcx       map[string][]uint32 // "idx/ingress"
	tc        map[string][]TCFilter
	names     map[uint32]string
	tcxOff    bool
	linksErr  error
	tcxErrFor int
}

func key(idx int, egress bool) string {
	if egress {
		return fmt.Sprintf("%d/egress", idx)
	}
	return fmt.Sprintf("%d/ingress", idx)
}

func (f *fakeKernel) Links() ([]LinkInfo, error) { return f.links, f.linksErr }
func (f *fakeKernel) TCX(idx int, egress bool) ([]uint32, bool, error) {
	if f.tcxOff {
		return nil, false, nil
	}
	if idx == f.tcxErrFor {
		return nil, true, errors.New("device busy")
	}
	return f.tcx[key(idx, egress)], true, nil
}
func (f *fakeKernel) TC(idx int, egress bool) ([]TCFilter, error) { return f.tc[key(idx, egress)], nil }
func (f *fakeKernel) ProgramName(id uint32) (string, error) {
	n, ok := f.names[id]
	if !ok {
		return "", errors.New("no such program")
	}
	return n, nil
}

var now = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func TestOwnerClassificationAndKernelNameTruncation(t *testing.T) {
	for name, want := range map[string]string{
		"netra_ingress": models.BPFOwnerNetra, "netra_edge_ingr": models.BPFOwnerNetra,
		"cil_from_container": models.BPFOwnerCilium, "cil_to_netdev": models.BPFOwnerCilium,
		"tc_probe": models.BPFOwnerOther, "": models.BPFOwnerOther,
	} {
		if got := OwnerOf(name); got != want {
			t.Errorf("OwnerOf(%q)=%q, want %q", name, got, want)
		}
	}
	// The kernel reports either the full name (BTF function info present, as on
	// current x86_64 and arm64 kernels) or its 15-character truncation. Both are
	// the same program; matching only one form reported every long-named Netra
	// program as missing on a real kernel.
	for _, reported := range []string{"netra_edge_ingress", "netra_edge_ingr"} {
		if !Same("netra_edge_ingress", reported) {
			t.Fatalf("%q must match netra_edge_ingress", reported)
		}
	}
	if !Same("netra_ingress", "netra_ingress") {
		t.Fatal("a short name matches itself")
	}
	if Same("netra_edge_ingress", "netra_edge_egres") || Same("netra_edge_ingress", "netra_edge_egress") || Same("netra_ingress", "cil_from_netdev") {
		t.Fatal("different programs must not match")
	}
}

func TestCollectListsOnlyProgrammedInterfacesAndClassifiesOwners(t *testing.T) {
	k := &fakeKernel{
		links: []LinkInfo{
			{Index: 1, Name: "lo", Loopback: true},
			{Index: 2, Name: "eth0", Type: "device", State: "up", XDPID: 50, XDPMode: "native"},
			{Index: 3, Name: "lxc1", Type: "veth", State: "up"},
			{Index: 4, Name: "idle0", Type: "device", State: "up"}, // nothing attached: not listed
		},
		tcx: map[string][]uint32{key(2, false): {10, 11}, key(2, true): {12}, key(3, false): {20}},
		tc:  map[string][]TCFilter{key(3, true): {{ID: 30, Name: "legacy_cls"}}},
		names: map[uint32]string{50: "netra_xdp_ingre", 10: "cil_from_netdev", 11: "netra_ingress", 12: "netra_egress",
			20: "cil_from_contai", 30: "legacy_cls"},
	}
	r := Collect(k, now)
	if !r.Available || !r.TCXSupported || r.Total != 2 || len(r.Interfaces) != 2 || r.Interfaces[0].Name != "eth0" {
		t.Fatalf("report=%+v", r)
	}
	eth := r.Interfaces[0]
	if eth.XDP == nil || eth.XDP.Mode != "native" || eth.XDP.Owner != models.BPFOwnerNetra || eth.XDP.ID != 50 {
		t.Fatalf("xdp=%+v", eth.XDP)
	}
	// Execution order is preserved: Cilium's program runs before Netra's.
	if len(eth.TCXIngress) != 2 || eth.TCXIngress[0].Owner != models.BPFOwnerCilium || eth.TCXIngress[1].Owner != models.BPFOwnerNetra {
		t.Fatalf("tcx ingress=%+v", eth.TCXIngress)
	}
	lxc := r.Interfaces[1]
	if len(lxc.TCEgress) != 1 || lxc.TCEgress[0].Name != "legacy_cls" || lxc.TCEgress[0].Owner != models.BPFOwnerOther {
		t.Fatalf("classic tc=%+v", lxc.TCEgress)
	}
}

func TestOldKernelWithoutTCXIsFlaggedNotReadAsEmpty(t *testing.T) {
	k := &fakeKernel{tcxOff: true, links: []LinkInfo{{Index: 2, Name: "eth0", XDPID: 5}}, names: map[uint32]string{5: "netra_xdp_ingre"}}
	r := Collect(k, now)
	if r.TCXSupported || len(r.Interfaces) != 1 {
		t.Fatalf("tcxSupported=%v interfaces=%d: an old kernel must say it cannot list TCX", r.TCXSupported, len(r.Interfaces))
	}
}

func TestOneFailingInterfaceDoesNotHideTheOthers(t *testing.T) {
	k := &fakeKernel{
		links:     []LinkInfo{{Index: 2, Name: "eth0"}, {Index: 3, Name: "eth1"}},
		tcx:       map[string][]uint32{key(3, false): {7}},
		names:     map[uint32]string{7: "netra_ingress"},
		tcxErrFor: 2,
	}
	r := Collect(k, now)
	if len(r.Interfaces) != 1 || r.Interfaces[0].Name != "eth1" || r.Error == "" {
		t.Fatalf("interfaces=%+v error=%q", r.Interfaces, r.Error)
	}
	// The interface that could not be read is named, so nothing concludes "detached" from its absence.
	if len(r.Failed) != 1 || r.Failed[0] != "eth0" {
		t.Fatalf("failed=%v", r.Failed)
	}
}

func TestUnresolvableProgramNameIsRecordedNotFatal(t *testing.T) {
	k := &fakeKernel{links: []LinkInfo{{Index: 2, Name: "eth0"}}, tcx: map[string][]uint32{key(2, false): {99}}}
	r := Collect(k, now)
	p := r.Interfaces[0].TCXIngress[0]
	if p.ID != 99 || p.Name != "" || p.Owner != models.BPFOwnerOther || r.Error == "" {
		t.Fatalf("program=%+v error=%q", p, r.Error)
	}
}

func TestListLinksFailureMakesTheInventoryUnavailable(t *testing.T) {
	r := Collect(&fakeKernel{linksErr: errors.New("netlink refused")}, now)
	if r.Available || r.Unavailable == "" {
		t.Fatalf("report=%+v", r)
	}
}

func TestInterfaceListIsCappedAndTheTotalIsHonest(t *testing.T) {
	k := &fakeKernel{tcx: map[string][]uint32{}, names: map[uint32]string{1: "cil_x"}}
	for i := 0; i < MaxInterfaces+30; i++ {
		k.links = append(k.links, LinkInfo{Index: i + 2, Name: fmt.Sprintf("lxc%04d", i)})
		k.tcx[key(i+2, false)] = []uint32{1}
	}
	r := Collect(k, now)
	if len(r.Interfaces) != MaxInterfaces || r.Total != MaxInterfaces+30 || r.Truncated != 30 {
		t.Fatalf("len=%d total=%d truncated=%d", len(r.Interfaces), r.Total, r.Truncated)
	}
}

func TestHashIgnoresTimeButNotContent(t *testing.T) {
	k := &fakeKernel{links: []LinkInfo{{Index: 2, Name: "eth0"}}, tcx: map[string][]uint32{key(2, false): {1}}, names: map[uint32]string{1: "netra_ingress", 2: "netra_egress"}}
	a := Collect(k, now)
	b := Collect(k, now.Add(time.Hour))
	if a.Hash == "" || a.Hash != b.Hash {
		t.Fatalf("hash changed with time alone: %q vs %q", a.Hash, b.Hash)
	}
	k.tcx[key(2, true)] = []uint32{2}
	if c := Collect(k, now); c.Hash == a.Hash {
		t.Fatal("hash did not change when a program was attached")
	}
}
