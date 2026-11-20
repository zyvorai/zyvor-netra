// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package nodeiso

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/zyvorai/netra/internal/models"
)

// Options configures Load.
type Options struct {
	// ObjectPath is the compiled bpf/netra_nodeiso.o.
	ObjectPath string
	// Interfaces receive the program at the head of their TCX egress chain.
	Interfaces []string
	// LoadOnly skips attaching (BPF_PROG_TEST_RUN tests).
	LoadOnly bool
	Log      *slog.Logger
}

// Isolator is the loaded, attached node-isolation program and the policy
// currently published into it.
type Isolator struct {
	coll     *ebpf.Collection
	links    []link.Link
	attached []string
	gen      uint32
	policyID string
	revision uint64
	mode     uint32
	demoted  string
}

// Load loads the object and attaches it to every interface it can. It
// returns an error only if no interface could be attached. The program
// starts with generation 0, i.e. passes everything until Apply.
func Load(opt Options) (*Isolator, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	spec, err := ebpf.LoadCollectionSpec(opt.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", opt.ObjectPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load node isolation program: %w", err)
	}
	iso := &Isolator{coll: coll}
	prog := coll.Programs["netra_nodeiso_egress"]
	if prog == nil {
		iso.Close()
		return nil, errors.New("program netra_nodeiso_egress missing from object")
	}
	for _, name := range opt.Interfaces {
		if opt.LoadOnly {
			break
		}
		ifc, err := net.InterfaceByName(name)
		if err != nil {
			opt.Log.Warn("node isolation interface lookup failed", "iface", name, "error", err)
			continue
		}
		// Head: TCX stops at the first definite verdict, and netra_egress
		// returns TC_ACT_OK for allowed traffic. Running first is the only
		// way this filter sees every packet.
		l, err := link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: prog, Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
		if err != nil {
			opt.Log.Warn("node isolation TCX attach failed", "iface", name, "error", err)
			continue
		}
		iso.links = append(iso.links, l)
		iso.attached = append(iso.attached, "nodeiso-tcx-egress:"+name)
	}
	if len(iso.links) == 0 && !opt.LoadOnly {
		iso.Close()
		return nil, fmt.Errorf("node isolation could not attach to any of %v", opt.Interfaces)
	}
	return iso, nil
}

// Program is the loaded classifier, for BPF_PROG_TEST_RUN.
func (i *Isolator) Program() *ebpf.Program { return i.coll.Programs["netra_nodeiso_egress"] }

// Attached lists the hooks the program runs on.
func (i *Isolator) Attached() []string { return append([]string(nil), i.attached...) }

// Apply publishes spec (nil = no policy) with implicit allow rules appended.
// A non-empty demoted reason runs an enforce policy in shadow. Unchanged
// input is a no-op. The new rules are written under a fresh generation and
// the config is switched last, so a packet never sees a half-written set;
// the previous generation is then removed.
func (i *Isolator) Apply(spec *models.NodeIsolationSpec, implicit []models.NodeIsolationRule, demoted string) error {
	if i == nil || i.coll == nil {
		return errors.New("node isolation is not loaded")
	}
	mode := ModeFor(spec, demoted)
	policyID, revision := "", uint64(0)
	if spec != nil {
		policyID, revision = spec.PolicyID, spec.Revision
	}
	if i.gen != 0 && mode == i.mode && policyID == i.policyID && revision == i.revision {
		i.demoted = demoted
		return nil
	}
	cfgMap, rulesMap, exemptMap := i.coll.Maps["nodeiso_cfg"], i.coll.Maps["nodeiso_rules"], i.coll.Maps["nodeiso_exempt"]
	if cfgMap == nil || rulesMap == nil || exemptMap == nil {
		return errors.New("node isolation maps missing")
	}
	gen := nextGeneration(i.gen)
	rules, exempt, err := compile(spec, implicit, gen)
	if err != nil {
		return err
	}
	for idx, r := range rules {
		if err := rulesMap.Put(ruleKey{Generation: gen, Index: uint32(idx)}, r); err != nil {
			return fmt.Errorf("write nodeiso_rules: %w", err)
		}
	}
	one := uint8(1)
	for _, k := range exempt {
		if err := exemptMap.Put(k, one); err != nil {
			return fmt.Errorf("write nodeiso_exempt: %w", err)
		}
	}
	cfg := config{Generation: gen, Mode: mode, RuleCount: uint32(len(rules))}
	if spec == nil {
		cfg = config{}
	}
	if err := cfgMap.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("publish nodeiso_cfg: %w", err)
	}
	i.gen, i.mode, i.policyID, i.revision, i.demoted = gen, mode, policyID, revision, demoted
	i.prune(gen)
	return nil
}

// prune deletes rule and exempt entries of every generation but keep.
func (i *Isolator) prune(keep uint32) {
	if m := i.coll.Maps["nodeiso_rules"]; m != nil {
		var k ruleKey
		var v rule
		var stale []ruleKey
		it := m.Iterate()
		for it.Next(&k, &v) {
			if k.Generation != keep {
				stale = append(stale, k)
			}
		}
		for _, k := range stale {
			_ = m.Delete(k)
		}
	}
	if m := i.coll.Maps["nodeiso_exempt"]; m != nil {
		var k exemptKey
		var v uint8
		var stale []exemptKey
		it := m.Iterate()
		for it.Next(&k, &v) {
			if k.Generation != keep {
				stale = append(stale, k)
			}
		}
		for _, k := range stale {
			_ = m.Delete(k)
		}
	}
}

func sum(v []uint64) uint64 {
	var t uint64
	for _, x := range v {
		t += x
	}
	return t
}

// Snapshot reads the counters and the top destinations outside the allow-list.
func (i *Isolator) Snapshot(top int) (*models.NodeIsolationStatus, error) {
	if i == nil || i.coll == nil {
		return nil, errors.New("node isolation is closed")
	}
	out := &models.NodeIsolationStatus{Attached: i.Attached(), PolicyID: i.policyID, Revision: i.revision, Demoted: i.demoted, Generation: i.gen}
	switch i.mode {
	case ModeShadow:
		out.Mode = models.NodeIsolationShadow
	case ModeEnforce:
		out.Mode = models.NodeIsolationEnforce
	}
	stats := i.coll.Maps["nodeiso_stats"]
	if stats == nil {
		return nil, errors.New("map nodeiso_stats missing")
	}
	for _, f := range []struct {
		dst  *uint64
		slot uint32
	}{
		{&out.Allowed, statAllowed}, {&out.WouldBlock, statWouldBlock}, {&out.Blocked, statBlocked},
		{&out.Exempt, statExempt}, {&out.WouldBlockBytes, statWouldBlockBytes}, {&out.BlockedBytes, statBlockedBytes},
	} {
		var v []uint64
		if err := stats.Lookup(f.slot, &v); err != nil {
			return nil, fmt.Errorf("read nodeiso_stats[%d]: %w", f.slot, err)
		}
		*f.dst = sum(v)
	}
	if m := i.coll.Maps["nodeiso_dests"]; m != nil {
		var k destKey
		var v destValue
		var dests []models.NodeIsolationDest
		it := m.Iterate()
		for it.Next(&k, &v) {
			dests = append(dests, models.NodeIsolationDest{Address: destAddress(k), Protocol: protocolName(k.Protocol), Port: k.Port, Packets: v.Packets, Bytes: v.Bytes})
		}
		out.Top = topDests(dests, top)
	}
	return out, nil
}

// Close detaches the program and frees the maps (the kernel then passes
// everything again: fail-open).
func (i *Isolator) Close() error {
	var errs []error
	for _, l := range i.links {
		errs = append(errs, l.Close())
	}
	i.links = nil
	if i.coll != nil {
		i.coll.Close()
		i.coll = nil
	}
	return errors.Join(errs...)
}
