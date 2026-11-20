// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package bpfattach takes a read-only inventory of the BPF programs attached to
// a node's interfaces: XDP (from the link's netlink attributes), TCX (the
// kernel's program query) and classic cls_bpf filters (netlink filter list).
//
// It exists because Netra resolves its interface list once, at startup, and
// attaches with bpf_link. If an interface is deleted and recreated, or a
// privileged process detaches or replaces a program, Netra's hook is gone and
// nothing says so: the agent still believes it is attached. Comparing what the
// agent believes (its hook list) with what the kernel reports (this inventory)
// is what makes that visible (internal/bpfattachdiag).
//
// It never attaches, detaches or replaces a program, and it never reads or
// touches a map or a program's bytecode: only the program id and the name the
// kernel already exposes. Programs owned by Cilium are listed, never modified.
//
// The collection logic is here, behind Source, so it is tested on any OS; the
// kernel calls are in source_linux.go.
package bpfattach

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// MaxInterfaces caps how many interfaces one report lists. A node with more
// programmed interfaces than this (a large Cilium node has one per pod) reports
// the first MaxInterfaces by name plus Total and Truncated.
const MaxInterfaces = 200

// maxFailed bounds how many unreadable interfaces one report names.
const maxFailed = 50

// kernelNameLen is BPF_OBJ_NAME_LEN-1: the kernel's own name field keeps only the
// first 15 characters, so "netra_edge_ingress" is "netra_edge_ingr" there. But
// when the kernel has BTF function info for the program (the case on current
// kernels, x86_64 and arm64 alike) the name comes back in full, so a reported
// name can be either form. A real-kernel test found this: matching only the
// truncated form reported every long-named Netra program as missing.
const kernelNameLen = 15

// LinkInfo is what the inventory needs to know about one interface.
type LinkInfo struct {
	Index    int
	Name     string
	Type     string
	State    string
	Loopback bool
	// XDPID is the attached XDP program's id, 0 when none; XDPMode is its mode.
	XDPID   uint32
	XDPMode string
}

// TCFilter is one classic cls_bpf filter.
type TCFilter struct {
	ID   uint32
	Name string
}

// Source is the kernel, as far as the inventory is concerned.
type Source interface {
	Links() ([]LinkInfo, error)
	// TCX returns the program ids at a TCX hook in execution order. supported is
	// false when the kernel cannot list TCX programs at all.
	TCX(index int, egress bool) (ids []uint32, supported bool, err error)
	TC(index int, egress bool) ([]TCFilter, error)
	ProgramName(id uint32) (string, error)
}

// OwnerOf classifies a program by name. The kernel truncates names to 15
// characters, which never removes these prefixes.
func OwnerOf(name string) string {
	switch {
	case strings.HasPrefix(name, "netra_"):
		return models.BPFOwnerNetra
	case strings.HasPrefix(name, "cil_"), strings.HasPrefix(name, "cilium_"):
		return models.BPFOwnerCilium
	}
	return models.BPFOwnerOther
}

// KernelName is the truncated form of a program name, as the kernel's fixed-size
// name field holds it.
func KernelName(name string) string {
	if len(name) > kernelNameLen {
		return name[:kernelNameLen]
	}
	return name
}

// Same reports whether a kernel-reported program name is the program the agent
// loaded under expected. The kernel may report the full name or its 15-character
// truncation depending on the kernel and whether BTF function info is present;
// both are the same program.
func Same(expected, reported string) bool {
	return reported == expected || reported == KernelName(expected)
}

// Collect inventories every non-loopback interface that has at least one
// program. A query that fails for one interface (it vanished, or the kernel
// refused) is recorded in Error and does not hide the others.
func Collect(src Source, now time.Time) models.BPFAttachReport {
	rep := models.BPFAttachReport{Available: true, TCXSupported: true, ObservedAt: now.UTC()}
	links, err := src.Links()
	if err != nil {
		return models.BPFAttachReport{Unavailable: "list links: " + err.Error(), ObservedAt: now.UTC()}
	}
	var errs []string
	failed := map[string]bool{}
	var current string
	note := func(what string, err error) {
		if err == nil {
			return
		}
		if current != "" && len(failed) < maxFailed {
			failed[current] = true
		}
		if len(errs) < 3 {
			errs = append(errs, what+": "+err.Error())
		}
	}
	prog := func(id uint32) models.BPFProgram {
		name, err := src.ProgramName(id)
		if err != nil {
			note("program name", err)
		}
		return models.BPFProgram{ID: id, Name: name, Owner: OwnerOf(name)}
	}
	var out []models.BPFInterfaceAttach
	for _, l := range links {
		if l.Loopback {
			continue
		}
		current = l.Name
		ia := models.BPFInterfaceAttach{Name: l.Name, Index: l.Index, Type: l.Type, State: l.State}
		if l.XDPID != 0 {
			p := prog(l.XDPID)
			p.Mode = l.XDPMode
			ia.XDP = &p
		}
		for _, egress := range []bool{false, true} {
			ids, supported, err := src.TCX(l.Index, egress)
			if !supported {
				rep.TCXSupported = false
			} else {
				note("tcx "+l.Name, err)
			}
			var list []models.BPFProgram
			for _, id := range ids {
				list = append(list, prog(id))
			}
			tc, err := src.TC(l.Index, egress)
			note("tc "+l.Name, err)
			var classic []models.BPFProgram
			for _, f := range tc {
				name := f.Name
				if name == "" && f.ID != 0 {
					name, _ = src.ProgramName(f.ID)
				}
				classic = append(classic, models.BPFProgram{ID: f.ID, Name: name, Owner: OwnerOf(name)})
			}
			if egress {
				ia.TCXEgress, ia.TCEgress = list, classic
			} else {
				ia.TCXIngress, ia.TCIngress = list, classic
			}
		}
		if ia.XDP == nil && len(ia.TCXIngress)+len(ia.TCXEgress)+len(ia.TCIngress)+len(ia.TCEgress) == 0 {
			continue
		}
		out = append(out, ia)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	rep.Total = len(out)
	if len(out) > MaxInterfaces {
		rep.Truncated = len(out) - MaxInterfaces
		out = out[:MaxInterfaces]
	}
	rep.Interfaces = out
	rep.Error = strings.Join(errs, "; ")
	for name := range failed {
		rep.Failed = append(rep.Failed, name)
	}
	sort.Strings(rep.Failed)
	rep.Hash = Hash(rep)
	return rep
}

// Hash identifies the inventory's content, ignoring when it was taken, so an
// unchanged inventory is not re-sent every report.
func Hash(r models.BPFAttachReport) string {
	r.ObservedAt = time.Time{}
	r.Hash, r.Unchanged = "", false
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
