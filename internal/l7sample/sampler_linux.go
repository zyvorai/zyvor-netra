// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package l7sample

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Options configures Load.
type Options struct {
	// ObjectPath is the compiled bpf/netra_l7sample.o.
	ObjectPath string
	// CgroupPath is the cgroup v2 directory the programs attach to (the node's
	// root cgroup in the agent; a scratch cgroup in tests).
	CgroupPath string
	// Ports maps a service port to the protocol expected on it.
	Ports map[uint16]Protocol
	// MinGap is the minimum time between samples of one flow and direction. Zero
	// samples every payload-bearing segment (tests only: it can flood the ring).
	MinGap time.Duration
	Log    *slog.Logger
}

// KernelStats are the in-kernel counters (mirroring L7S_STAT_*): how many
// payload-bearing segments on a configured port were seen, how many were sent up,
// and why the rest were not. Eligible/Emitted is the factor to scale sampled
// counts back to an estimate of the real rate.
type KernelStats struct {
	Eligible    uint64
	Emitted     uint64
	RateLimited uint64
	RingbufFull uint64
	LoadFail    uint64
}

// Sampler is the loaded, attached sampler.
type Sampler struct {
	coll  *ebpf.Collection
	links []link.Link
	log   *slog.Logger
}

// Load loads the object, writes the port and rate configuration, and attaches the
// egress and ingress programs to the cgroup.
func Load(opt Options) (*Sampler, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if len(opt.Ports) == 0 {
		return nil, errors.New("no service ports configured")
	}
	spec, err := ebpf.LoadCollectionSpec(opt.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", opt.ObjectPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load L7 sampler (verifier?): %w", err)
	}
	s := &Sampler{coll: coll, log: opt.Log}

	for port, proto := range opt.Ports {
		if proto == ProtoUnknown {
			continue
		}
		if err := coll.Maps["l7s_ports"].Put(port, uint8(proto)); err != nil {
			s.Close()
			return nil, fmt.Errorf("configure port %d: %w", port, err)
		}
	}
	if err := coll.Maps["l7s_cfg"].Put(uint32(0), uint64(opt.MinGap.Nanoseconds())); err != nil {
		s.Close()
		return nil, fmt.Errorf("configure rate limit: %w", err)
	}
	for _, at := range []struct {
		prog   string
		attach ebpf.AttachType
	}{{"netra_l7s_egress", ebpf.AttachCGroupInetEgress}, {"netra_l7s_ingress", ebpf.AttachCGroupInetIngress}} {
		p := coll.Programs[at.prog]
		if p == nil {
			s.Close()
			return nil, fmt.Errorf("program %s missing from object", at.prog)
		}
		l, err := link.AttachCgroup(link.CgroupOptions{Path: opt.CgroupPath, Attach: at.attach, Program: p})
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %s to %s: %w", at.prog, opt.CgroupPath, err)
		}
		s.links = append(s.links, l)
	}
	return s, nil
}

// Run reads samples until ctx is done, calling fn for each. The Sample's Data is a
// view valid only during the call. Blocks; run it in its own goroutine.
func (s *Sampler) Run(ctx context.Context, fn func(Sample)) {
	rd, err := ringbuf.NewReader(s.coll.Maps["l7s_events"])
	if err != nil {
		s.log.Warn("open l7s_events ring buffer", "error", err)
		return
	}
	defer rd.Close()
	go func() { <-ctx.Done(); _ = rd.Close() }()
	for {
		rec, err := rd.Read()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, ringbuf.ErrClosed) {
				s.log.Warn("read l7s_events", "error", err)
			}
			return
		}
		smp, err := DecodeEvent(rec.RawSample)
		if err != nil {
			continue
		}
		fn(smp)
	}
}

// KernelStats reads the in-kernel counters, summed across CPUs.
func (s *Sampler) KernelStats() (KernelStats, error) {
	m := s.coll.Maps["l7s_stats"]
	if m == nil {
		return KernelStats{}, errors.New("map l7s_stats missing")
	}
	get := func(slot uint32) (uint64, error) {
		var per []uint64
		if err := m.Lookup(slot, &per); err != nil {
			return 0, err
		}
		var t uint64
		for _, v := range per {
			t += v
		}
		return t, nil
	}
	var out KernelStats
	for _, f := range []struct {
		dst  *uint64
		slot uint32
	}{{&out.Eligible, 0}, {&out.Emitted, 1}, {&out.RateLimited, 2}, {&out.RingbufFull, 3}, {&out.LoadFail, 4}} {
		v, err := get(f.slot)
		if err != nil {
			return KernelStats{}, fmt.Errorf("read l7s_stats[%d]: %w", f.slot, err)
		}
		*f.dst = v
	}
	return out, nil
}

// ProgramStats reports how many times the egress and ingress programs have run
// and the total time they spent, from the kernel's own BPF accounting. Both are
// zero unless run-time statistics are enabled (ebpf.EnableStats with
// unix.BPF_STATS_RUN_TIME, or kernel.bpf_stats_enabled=1).
func (s *Sampler) ProgramStats() (runs uint64, spent time.Duration, err error) {
	if s == nil || s.coll == nil {
		return 0, 0, errors.New("sampler is closed")
	}
	for _, name := range []string{"netra_l7s_egress", "netra_l7s_ingress"} {
		p := s.coll.Programs[name]
		if p == nil {
			return 0, 0, fmt.Errorf("program %s missing", name)
		}
		st, err := p.Stats()
		if err != nil {
			return 0, 0, err
		}
		runs += st.RunCount
		spent += st.Runtime
	}
	return runs, spent, nil
}

// Close detaches the programs and frees the maps.
func (s *Sampler) Close() error {
	var errs []error
	for _, l := range s.links {
		errs = append(errs, l.Close())
	}
	s.links = nil
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	return errors.Join(errs...)
}
