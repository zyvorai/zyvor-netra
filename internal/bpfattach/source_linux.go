// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package bpfattach

import (
	"errors"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NewSource reads the running kernel. It needs the same privilege as the agent
// already has (CAP_BPF/CAP_SYS_ADMIN to resolve program ids, CAP_NET_ADMIN for
// the filter dump) and changes nothing.
func NewSource() Source { return &kernelSource{names: map[uint32]string{}} }

type kernelSource struct {
	mu    sync.Mutex
	names map[uint32]string // program id -> name; an id names one program forever
}

// maxNameCache bounds the id->name cache: ids are never reused for a different
// program, but a node that churns programs would otherwise grow it forever.
const maxNameCache = 8192

func (k *kernelSource) Links() ([]LinkInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := make([]LinkInfo, 0, len(links))
	for _, l := range links {
		a := l.Attrs()
		li := LinkInfo{
			Index: a.Index, Name: a.Name, Type: l.Type(), State: a.OperState.String(),
			Loopback: a.Flags&net.FlagLoopback != 0,
		}
		if a.Xdp != nil && a.Xdp.Attached {
			li.XDPID = a.Xdp.ProgId
			li.XDPMode = xdpMode(a.Xdp.AttachMode)
		}
		out = append(out, li)
	}
	return out, nil
}

// xdpMode names IFLA_XDP_ATTACHED (enum xdp_attached_mode).
func xdpMode(m uint32) string {
	switch m {
	case 1:
		return "native"
	case 2:
		return "generic"
	case 3:
		return "offload"
	case 4:
		return "multi"
	}
	return ""
}

func (k *kernelSource) TCX(index int, egress bool) ([]uint32, bool, error) {
	at := ebpf.AttachTCXIngress
	if egress {
		at = ebpf.AttachTCXEgress
	}
	res, err := link.QueryPrograms(link.QueryOptions{Target: index, Attach: at})
	if err != nil {
		// Before kernel 6.6 there is no TCX: "cannot list" is not "nothing attached".
		if errors.Is(err, link.ErrNotSupported) || errors.Is(err, ebpf.ErrNotSupported) ||
			errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return nil, false, nil
		}
		return nil, true, err
	}
	ids := make([]uint32, 0, len(res.Programs))
	for _, p := range res.Programs {
		ids = append(ids, uint32(p.ID))
	}
	return ids, true, nil
}

func (k *kernelSource) TC(index int, egress bool) ([]TCFilter, error) {
	parent := uint32(netlink.HANDLE_MIN_INGRESS)
	if egress {
		parent = uint32(netlink.HANDLE_MIN_EGRESS)
	}
	l, err := netlink.LinkByIndex(index)
	if err != nil {
		return nil, err
	}
	filters, err := netlink.FilterList(l, parent)
	if err != nil {
		// No clsact qdisc on the interface is the normal case, not a fault.
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENODEV) {
			return nil, nil
		}
		return nil, err
	}
	var out []TCFilter
	for _, f := range filters {
		if b, ok := f.(*netlink.BpfFilter); ok {
			out = append(out, TCFilter{ID: uint32(b.Id), Name: b.Name})
		}
	}
	return out, nil
}

func (k *kernelSource) ProgramName(id uint32) (string, error) {
	k.mu.Lock()
	if n, ok := k.names[id]; ok {
		k.mu.Unlock()
		return n, nil
	}
	k.mu.Unlock()
	p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return "", err
	}
	defer p.Close()
	info, err := p.Info()
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	if len(k.names) >= maxNameCache {
		clear(k.names)
	}
	k.names[id] = info.Name
	k.mu.Unlock()
	return info.Name, nil
}
