// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package rtnlactor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// defaultBTF is where a BTF-enabled kernel publishes its type information. An
// fentry program is resolved against it (function address and signature), so a
// kernel without it cannot run this sensor.
const defaultBTF = "/sys/kernel/btf/vmlinux"

// Options configures Load.
type Options struct {
	// ObjectPath is the compiled bpf/netra_rtnl.o.
	ObjectPath string
	// BTFPath overrides defaultBTF (tests).
	BTFPath string
	// NetNS is the network namespace (inode) whose requests are recorded; 0 means this
	// process's own, which is the right answer for the agent (hostNetwork) and for tests.
	NetNS uint32
	Log   *slog.Logger
}

// Sensor is a loaded, attached rtnetlink_rcv_msg fentry program.
type Sensor struct {
	coll *ebpf.Collection
	link link.Link
	rd   *ringbuf.Reader
	log  *slog.Logger
}

// Load loads and attaches the program. Every failure is returned with its reason:
// the caller reports the feature as unavailable and carries on, since the netlink
// recorder does not depend on it.
func Load(opt Options) (*Sensor, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	btf := opt.BTFPath
	if btf == "" {
		btf = defaultBTF
	}
	if _, err := os.Stat(btf); err != nil {
		return nil, fmt.Errorf("kernel BTF is not available (%s): the fentry on rtnetlink_rcv_msg cannot be resolved without it", btf)
	}
	spec, err := ebpf.LoadCollectionSpec(opt.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", opt.ObjectPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load rtnl programs: %w", err)
	}
	prog, events := coll.Programs["netra_rtnl_msg"], coll.Maps["rtnl_events"]
	if prog == nil || events == nil {
		coll.Close()
		return nil, errors.New("bpf object lacks netra_rtnl_msg or rtnl_events (out of date?)")
	}
	// Name the one namespace to record BEFORE attaching, so the program never records
	// another namespace's requests, whose interface indexes could collide.
	netns := opt.NetNS
	if netns == 0 {
		netns = SelfNetNS()
	}
	if cfg := coll.Maps["rtnl_config"]; cfg != nil && netns != 0 {
		if err := cfg.Put(uint32(0), netns); err != nil {
			coll.Close()
			return nil, fmt.Errorf("set the recorded network namespace: %w", err)
		}
	}
	l, err := link.AttachTracing(link.TracingOptions{Program: prog})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach fentry rtnetlink_rcv_msg: %w", err)
	}
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		_ = l.Close()
		coll.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return &Sensor{coll: coll, link: l, rd: rd, log: opt.Log}, nil
}

// Run reads records until ctx is done or the sensor is closed, calling emit for
// each. emit must not block: a slow consumer would back the ring buffer up, and the
// kernel drops (and counts) rather than waits.
func (s *Sensor) Run(ctx context.Context, emit func(Record)) {
	go func() {
		<-ctx.Done()
		_ = s.rd.Close()
	}()
	for {
		raw, err := s.rd.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				s.log.Warn("rtnl actor ring buffer read failed", "error", err)
			}
			return
		}
		rec, err := Parse(raw.RawSample)
		if err != nil {
			continue
		}
		rec.Wall = wallTime(rec.TS)
		emit(rec)
	}
}

// wallTime converts a CLOCK_MONOTONIC timestamp to wall clock time. The two
// clocks are read together, so the error is the time between them: microseconds.
func wallTime(ts uint64) time.Time {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return time.Now().UTC()
	}
	ago := time.Duration(uint64(now.Nano()) - ts)
	if ago < 0 {
		ago = 0
	}
	return time.Now().Add(-ago).UTC()
}

// Dropped is how many requests the kernel could not record because the ring
// buffer was full.
func (s *Sensor) Dropped() (uint64, error) {
	var v uint64
	if err := s.coll.Maps["rtnl_stats"].Lookup(uint32(0), &v); err != nil {
		return 0, err
	}
	return v, nil
}

// Close detaches the program and releases everything.
func (s *Sensor) Close() error {
	if s == nil {
		return nil
	}
	_ = s.rd.Close()
	err := s.link.Close()
	s.coll.Close()
	return err
}
