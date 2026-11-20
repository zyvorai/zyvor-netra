// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package tcpevents

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/zyvorai/netra/internal/tpformat"
)

// Options configures Load.
type Options struct {
	// ObjectPath is the compiled bpf/netra_tcpevents.o.
	ObjectPath string
	// ReadFormat returns a tracepoint's parsed format. Nil means the running
	// kernel's tracefs (tpformat.Read); tests inject fixtures.
	ReadFormat func(group, event string) (*tpformat.Format, error)
	Log        *slog.Logger
}

// Sensor is a loaded, attached set of TCP event tracepoints.
type Sensor struct {
	coll     *ebpf.Collection
	links    []link.Link
	attached []string
	skipped  map[string]string
}

// Load compiles nothing and assumes nothing about the kernel: it derives each
// tracepoint's record layout from the running kernel, drops any sensor whose
// layout cannot be established (with the reason), patches the layouts into the
// object's read-only data, loads, and attaches. It returns an error only if no
// sensor could be attached at all.
func Load(opt Options) (*Sensor, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	read := opt.ReadFormat
	if read == nil {
		read = tpformat.Read
	}
	spec, err := ebpf.LoadCollectionSpec(opt.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", opt.ObjectPath, err)
	}

	skipped := map[string]string{}
	var usable []Tracepoint
	for _, tp := range Tracepoints {
		f, err := read(tp.Group, tp.Event)
		if err != nil {
			skipped[tp.Name] = err.Error()
			continue
		}
		l, err := LayoutFor(tp, f)
		if err != nil {
			skipped[tp.Name] = err.Error()
			continue
		}
		v := spec.Variables[tp.Var]
		if v == nil {
			skipped[tp.Name] = "object has no variable " + tp.Var
			continue
		}
		if err := v.Set(l); err != nil {
			skipped[tp.Name] = fmt.Sprintf("set %s: %v", tp.Var, err)
			continue
		}
		usable = append(usable, tp)
	}
	// A program that will not be attached is not loaded either: it cannot
	// then fail the verifier on behalf of the ones that can run.
	keep := map[string]bool{}
	for _, tp := range usable {
		keep[tp.Program] = true
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	if len(usable) == 0 {
		return nil, fmt.Errorf("no tracepoint layout could be established: %v", skipped)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load TCP event programs: %w", err)
	}
	s := &Sensor{coll: coll, skipped: skipped}
	for _, tp := range usable {
		p := coll.Programs[tp.Program]
		if p == nil {
			s.skipped[tp.Name] = "program " + tp.Program + " missing from object"
			continue
		}
		l, err := link.Tracepoint(tp.Group, tp.Event, p, nil)
		if err != nil {
			s.skipped[tp.Name] = fmt.Sprintf("attach %s:%s: %v", tp.Group, tp.Event, err)
			continue
		}
		s.links = append(s.links, l)
		s.attached = append(s.attached, tp.Name)
	}
	if len(s.attached) == 0 {
		_ = s.Close()
		return nil, fmt.Errorf("no TCP event tracepoint could be attached: %v", s.skipped)
	}
	for name, why := range s.skipped {
		opt.Log.Warn("TCP event sensor skipped", "sensor", name, "reason", why)
	}
	return s, nil
}

// Attached lists the sensors that are running.
func (s *Sensor) Attached() []string { return append([]string(nil), s.attached...) }

// Skipped maps each sensor that is not running to the reason.
func (s *Sensor) Skipped() map[string]string {
	out := make(map[string]string, len(s.skipped))
	for k, v := range s.skipped {
		out[k] = v
	}
	return out
}

// Close detaches the tracepoints and frees the maps.
func (s *Sensor) Close() error {
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

// flowKey/flowValue mirror struct tcpev_flow_key/tcpev_flow_value byte for byte.
type flowKey struct {
	Family uint8
	_      [3]uint8
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
}

type flowValue struct {
	Retrans, RSTSent, RSTRecv, LastNS uint64
}

// Stat slots, mirroring TCPEV_STAT_* in the object.
const (
	statRetrans = iota
	statRSTSent
	statRSTRecv
	statTransitions
	statReadErr
	statBadFamily
	statMapFull
)

func sum(v []uint64) uint64 {
	var t uint64
	for _, x := range v {
		t += x
	}
	return t
}

// Snapshot reads the cumulative state. topFlows bounds the flow list, ordered
// by retransmits plus resets (busiest first).
func (s *Sensor) Snapshot(topFlows int) (*Snapshot, error) {
	if s == nil || s.coll == nil {
		return nil, errors.New("TCP event sensor is closed")
	}
	if topFlows <= 0 {
		topFlows = 50
	}
	out := &Snapshot{Attached: s.Attached(), Skipped: s.Skipped()}
	if len(out.Skipped) == 0 {
		out.Skipped = nil
	}

	stats := s.coll.Maps["tcp_ev_stats"]
	if stats == nil {
		return nil, errors.New("map tcp_ev_stats missing")
	}
	slot := func(i int) (uint64, error) {
		var v []uint64
		if err := stats.Lookup(uint32(i), &v); err != nil {
			return 0, err
		}
		return sum(v), nil
	}
	for _, f := range []struct {
		dst  *uint64
		slot int
	}{
		{&out.Totals.Retransmits, statRetrans}, {&out.Totals.RSTSent, statRSTSent}, {&out.Totals.RSTReceived, statRSTRecv},
		{&out.Totals.StateTransitions, statTransitions}, {&out.Totals.ReadErrors, statReadErr},
		{&out.Totals.BadFamily, statBadFamily}, {&out.Totals.MapFull, statMapFull},
	} {
		v, err := slot(f.slot)
		if err != nil {
			return nil, fmt.Errorf("read tcp_ev_stats[%d]: %w", f.slot, err)
		}
		*f.dst = v
	}

	if m := s.coll.Maps["tcp_ev_transitions"]; m != nil {
		var k uint32
		var v []uint64
		it := m.Iterate()
		for it.Next(&k, &v) {
			if n := sum(v); n > 0 {
				out.Transitions = append(out.Transitions, Transition{From: StateName(uint8(k >> 4)), To: StateName(uint8(k & 15)), Count: n})
			}
		}
		if err := it.Err(); err != nil {
			return nil, fmt.Errorf("read tcp_ev_transitions: %w", err)
		}
		sort.Slice(out.Transitions, func(i, j int) bool {
			if out.Transitions[i].Count != out.Transitions[j].Count {
				return out.Transitions[i].Count > out.Transitions[j].Count
			}
			return out.Transitions[i].From+out.Transitions[i].To < out.Transitions[j].From+out.Transitions[j].To
		})
	}

	if m := s.coll.Maps["tcp_ev_flows"]; m != nil {
		var k flowKey
		var v flowValue
		it := m.Iterate()
		for it.Next(&k, &v) {
			f := Flow{SrcPort: k.Sport, DstPort: k.Dport, Retransmits: v.Retrans, RSTSent: v.RSTSent, RSTReceived: v.RSTRecv, LastSeenNS: v.LastNS}
			if k.Family == 6 {
				f.Family, f.Src, f.Dst = "ipv6", net.IP(k.Saddr[:]).String(), net.IP(k.Daddr[:]).String()
			} else {
				f.Family, f.Src, f.Dst = "ipv4", net.IP(k.Saddr[:4]).String(), net.IP(k.Daddr[:4]).String()
			}
			out.Flows = append(out.Flows, f)
		}
		if err := it.Err(); err != nil {
			return nil, fmt.Errorf("read tcp_ev_flows: %w", err)
		}
		sort.Slice(out.Flows, func(i, j int) bool {
			a, b := out.Flows[i], out.Flows[j]
			ta, tb := a.Retransmits+a.RSTSent+a.RSTReceived, b.Retransmits+b.RSTSent+b.RSTReceived
			if ta != tb {
				return ta > tb
			}
			return a.LastSeenNS > b.LastSeenNS
		})
		if len(out.Flows) > topFlows {
			out.Flows = out.Flows[:topFlows]
		}
	}
	return out, nil
}
