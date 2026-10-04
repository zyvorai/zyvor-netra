// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package dropinfo

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/zyvorai/netra/internal/ksym"
	"github.com/zyvorai/netra/internal/tpformat"
)

// defaultBTF is where a BTF-enabled kernel publishes its type information.
const defaultBTF = "/sys/kernel/btf/vmlinux"

// Options configures Load.
type Options struct {
	// ObjectPath is the compiled bpf/netra_dropinfo.o.
	ObjectPath string
	// ReadFormat returns a tracepoint's parsed format. Nil means the running
	// kernel's tracefs (tpformat.Read); tests inject fixtures.
	ReadFormat func(group, event string) (*tpformat.Format, error)
	// BTFPath is the kernel BTF file that must exist for the sk_buff field
	// offsets to be relocated. Empty means /sys/kernel/btf/vmlinux.
	BTFPath string
	// Symbols resolves drop locations. Nil means a Resolver on /proc/kallsyms.
	Symbols *ksym.Resolver
	Log     *slog.Logger
}

// Sensor is a loaded, attached kfree_skb tracepoint program.
type Sensor struct {
	coll        *ebpf.Collection
	link        link.Link
	reasonNames map[int]string
	syms        *ksym.Resolver
}

// Load checks that the kernel has BTF (the object's sk_buff reads are CO-RE
// relocated), derives the tracepoint's record layout from the running kernel,
// patches it in, loads and attaches. Every failure is returned with its reason;
// the caller treats it as "this feature is unavailable", never as fatal to the
// agent unless the operator required it.
func Load(opt Options) (*Sensor, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	read := opt.ReadFormat
	if read == nil {
		read = tpformat.Read
	}
	btfPath := opt.BTFPath
	if btfPath == "" {
		btfPath = defaultBTF
	}
	if _, err := os.Stat(btfPath); err != nil {
		return nil, fmt.Errorf("kernel BTF not available (%s): the drop tuple is read from sk_buff, whose field offsets need BTF: %w", btfPath, err)
	}

	f, err := read(TPGroup, TPEvent)
	if err != nil {
		return nil, fmt.Errorf("read %s:%s layout: %w", TPGroup, TPEvent, err)
	}
	layout, err := LayoutFor(f)
	if err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpec(opt.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", opt.ObjectPath, err)
	}
	v := spec.Variables["L_kfree"]
	if v == nil {
		return nil, errors.New("object has no variable L_kfree")
	}
	if err := v.Set(layout); err != nil {
		return nil, fmt.Errorf("set L_kfree: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load drop info program (verifier, or sk_buff relocation against kernel BTF): %w", err)
	}
	prog := coll.Programs["netra_drop_info"]
	if prog == nil {
		coll.Close()
		return nil, errors.New("program netra_drop_info missing from object")
	}
	lnk, err := link.Tracepoint(TPGroup, TPEvent, prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach %s:%s: %w", TPGroup, TPEvent, err)
	}
	syms := opt.Symbols
	if syms == nil {
		syms = &ksym.Resolver{}
	}
	return &Sensor{coll: coll, link: lnk, reasonNames: ReasonNames(f), syms: syms}, nil
}

// Stats reports how many times the program has run and the total time it spent,
// from the kernel's own BPF accounting. Both are zero unless run-time statistics
// are enabled (ebpf.EnableStats(unix.BPF_STATS_RUN_TIME), or
// kernel.bpf_stats_enabled=1), which the kernel leaves off because it costs a
// little on every run.
func (s *Sensor) Stats() (runs uint64, spent time.Duration, err error) {
	if s == nil || s.coll == nil {
		return 0, 0, errClosed
	}
	prog := s.coll.Programs["netra_drop_info"]
	if prog == nil {
		return 0, 0, errors.New("program netra_drop_info missing")
	}
	st, err := prog.Stats()
	if err != nil {
		return 0, 0, err
	}
	return st.RunCount, st.Runtime, nil
}

// Close detaches the tracepoint and frees the maps.
func (s *Sensor) Close() error {
	var err error
	if s.link != nil {
		err = s.link.Close()
		s.link = nil
	}
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	return err
}

// dropKey/dropVal/siteKey mirror the structs in the object byte for byte.
type dropKey struct {
	Reason uint32
	Family uint8
	Proto  uint8
	_      uint16
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
}

type dropVal struct {
	Count, Location, LastNS uint64
}

type rawFlow struct {
	k dropKey
	v dropVal
}

// flowBatch is the number of drop_flows entries read per batch syscall.
const flowBatch = 1024

// readFlows reads drop_flows with batch lookups, one syscall per flowBatch
// entries, and falls back to per-key iteration on kernels without batch
// support for the map type.
func readFlows(m *ebpf.Map) ([]rawFlow, error) {
	var out []rawFlow
	var cursor ebpf.MapBatchCursor
	keys := make([]dropKey, flowBatch)
	vals := make([]dropVal, flowBatch)
	for {
		n, err := m.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			out = append(out, rawFlow{keys[i], vals[i]})
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return out, nil
		}
		if err != nil {
			if len(out) == 0 && (errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, unix.EINVAL)) {
				return iterateFlows(m)
			}
			return nil, err
		}
	}
}

func iterateFlows(m *ebpf.Map) ([]rawFlow, error) {
	var out []rawFlow
	var k dropKey
	var v dropVal
	it := m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, rawFlow{k, v})
	}
	return out, it.Err()
}

type siteKey struct {
	Reason uint32
	_      uint32
	Loc    uint64
}

// Stat slots, mirroring DROP_STAT_* in the object.
const (
	statTotal = iota
	statTuple
	statNoTuple
	statNoHeader
	statReadErr
	statMapFull
)

func sum(v []uint64) uint64 {
	var t uint64
	for _, x := range v {
		t += x
	}
	return t
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	}
	return fmt.Sprintf("proto-%d", p)
}

// Snapshot reads the cumulative state. topFlows and topSites bound the lists
// (busiest first).
func (s *Sensor) Snapshot(topFlows, topSites int) (*Snapshot, error) {
	if s == nil || s.coll == nil {
		return nil, errClosed
	}
	if topFlows <= 0 {
		topFlows = 50
	}
	if topSites <= 0 {
		topSites = 50
	}
	out := &Snapshot{Attached: true, Reasons: map[string]uint64{}}

	stats := s.coll.Maps["drop_stats"]
	if stats == nil {
		return nil, errors.New("map drop_stats missing")
	}
	for _, f := range []struct {
		dst  *uint64
		slot uint32
	}{
		{&out.Totals.Drops, statTotal}, {&out.Totals.WithTuple, statTuple}, {&out.Totals.NoTuple, statNoTuple},
		{&out.Totals.NoHeader, statNoHeader}, {&out.Totals.ReadError, statReadErr}, {&out.Totals.MapFull, statMapFull},
	} {
		var v []uint64
		if err := stats.Lookup(f.slot, &v); err != nil {
			return nil, fmt.Errorf("read drop_stats[%d]: %w", f.slot, err)
		}
		*f.dst = sum(v)
	}

	// Collect raw rows first so every location is resolved in one batch.
	var flows []rawFlow
	if m := s.coll.Maps["drop_flows"]; m != nil {
		var err error
		if flows, err = readFlows(m); err != nil {
			return nil, fmt.Errorf("read drop_flows: %w", err)
		}
	}
	// Only the busiest flows are reported, so rank the raw rows and drop the
	// rest before resolving locations and formatting addresses.
	sort.Slice(flows, func(i, j int) bool {
		a, b := flows[i].v, flows[j].v
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.LastNS > b.LastNS
	})
	if len(flows) > topFlows {
		flows = flows[:topFlows]
	}
	type rawSite struct {
		k siteKey
		n uint64
	}
	var sites []rawSite
	if m := s.coll.Maps["drop_sites"]; m != nil {
		var k siteKey
		var n uint64
		it := m.Iterate()
		for it.Next(&k, &n) {
			sites = append(sites, rawSite{k, n})
		}
		if err := it.Err(); err != nil {
			return nil, fmt.Errorf("read drop_sites: %w", err)
		}
	}

	var addrs []uint64
	for _, f := range flows {
		if f.v.Location != 0 {
			addrs = append(addrs, f.v.Location)
		}
	}
	for _, st := range sites {
		if st.k.Loc != 0 {
			addrs = append(addrs, st.k.Loc)
		}
	}
	names := s.syms.Resolve(addrs)
	loc := func(a uint64) string {
		if a == 0 {
			return ""
		}
		return names[a]
	}

	agg := map[[2]string]uint64{}
	for _, st := range sites {
		reason := ReasonName(s.reasonNames, st.k.Reason)
		out.Reasons[reason] += st.n
		agg[[2]string{reason, loc(st.k.Loc)}] += st.n
	}
	for k, n := range agg {
		out.Sites = append(out.Sites, Site{Reason: k[0], Location: k[1], Count: n})
	}
	sort.Slice(out.Sites, func(i, j int) bool {
		a, b := out.Sites[i], out.Sites[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Location < b.Location
	})
	if len(out.Sites) > topSites {
		out.Sites = out.Sites[:topSites]
	}

	for _, rf := range flows {
		f := Flow{
			SrcPort: rf.k.Sport, DstPort: rf.k.Dport,
			Reason: ReasonName(s.reasonNames, rf.k.Reason), Count: rf.v.Count,
			Location: loc(rf.v.Location), LastSeenNS: rf.v.LastNS,
		}
		switch rf.k.Family {
		case 4:
			f.Family, f.Src, f.Dst = "ipv4", net.IP(rf.k.Saddr[:4]).String(), net.IP(rf.k.Daddr[:4]).String()
			f.Proto = protoName(rf.k.Proto)
		case 6:
			f.Family, f.Src, f.Dst = "ipv6", net.IP(rf.k.Saddr[:]).String(), net.IP(rf.k.Daddr[:]).String()
			f.Proto = protoName(rf.k.Proto)
		}
		out.Flows = append(out.Flows, f)
	}
	if len(out.Reasons) == 0 {
		out.Reasons = nil
	}
	return out, nil
}
