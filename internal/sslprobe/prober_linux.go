// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package sslprobe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Options configures Load.
type Options struct {
	// ObjectPath is the compiled bpf/netra_ssl.o.
	ObjectPath string
	// ProcRoot is where processes are discovered. Empty means /proc, which must be
	// the host's (hostPID in a container) to see other workloads' libraries.
	ProcRoot string
	// MinGap is the minimum time between samples of one connection and direction.
	MinGap time.Duration
	// Comms, when non-empty, restricts observation to processes with these command
	// names (the kernel's 15-character comm). The check is made in the kernel
	// before any plaintext byte is copied.
	Comms []string
	Log   *slog.Logger
}

// KernelStats are the in-kernel counters (mirroring SSL_STAT_*).
type KernelStats struct {
	Eligible     uint64 // calls that carried data
	Emitted      uint64
	RateLimited  uint64
	RingbufFull  uint64
	ReadFail     uint64
	CommFiltered uint64 // skipped by the process allowlist
}

// probe is one attachment: which program on which symbol.
type probe struct {
	sym, prog string
	ret       bool
}

// SSL_read and SSL_read_ex are sampled on return, because that is when the
// plaintext exists, so each needs its entry and return programs.
var probes = []probe{
	{"SSL_write", "netra_ssl_write", false},
	{"SSL_write_ex", "netra_ssl_write_ex", false},
	{"SSL_read", "netra_ssl_read", false},
	{"SSL_read", "netra_ssl_read_ret", true},
	{"SSL_read_ex", "netra_ssl_read_ex", false},
	{"SSL_read_ex", "netra_ssl_read_ex_ret", true},
}

// Prober is a loaded sampler that attaches to the libssl files it finds.
type Prober struct {
	coll     *ebpf.Collection
	log      *slog.Logger
	procRoot string

	mu       sync.Mutex
	attached map[string]*attachment // by Lib.Key
}

type attachment struct {
	path  string
	links []link.Link
}

// Load loads the object for this architecture and writes its configuration. It
// attaches nothing: call Scan.
func Load(opt Options) (*Prober, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	layout, err := LayoutFor(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpec(opt.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", opt.ObjectPath, err)
	}
	v := spec.Variables["L"]
	if v == nil {
		return nil, errors.New("object has no variable L")
	}
	if err := v.Set(layout); err != nil {
		return nil, fmt.Errorf("set register layout: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load TLS sampler (verifier?): %w", err)
	}
	p := &Prober{coll: coll, log: opt.Log, procRoot: opt.ProcRoot, attached: map[string]*attachment{}}
	if p.procRoot == "" {
		p.procRoot = "/proc"
	}
	if err := coll.Maps["ssl_cfg"].Put(uint32(0), uint64(opt.MinGap.Nanoseconds())); err != nil {
		p.Close()
		return nil, fmt.Errorf("configure rate limit: %w", err)
	}
	useAllow := uint64(0)
	for _, c := range opt.Comms {
		if c == "" {
			continue
		}
		var key [16]byte
		copy(key[:15], c) // the kernel's comm is at most 15 characters plus NUL
		if err := coll.Maps["ssl_comm_allow"].Put(key, uint8(1)); err != nil {
			p.Close()
			return nil, fmt.Errorf("configure process allowlist: %w", err)
		}
		useAllow = 1
	}
	if err := coll.Maps["ssl_cfg"].Put(uint32(1), useAllow); err != nil {
		p.Close()
		return nil, fmt.Errorf("configure process allowlist: %w", err)
	}
	return p, nil
}

// Scan finds every libssl mapped by a running process and attaches to those not
// yet attached. It returns the paths newly attached. A library that lacks the
// symbols (a build without SSL_read, say) is skipped, not an error.
func (p *Prober) Scan() ([]string, error) {
	var added []string
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.coll == nil {
		return nil, errors.New("prober is closed")
	}
	for _, lib := range Discover(p.procRoot) {
		if _, done := p.attached[lib.Key]; done {
			continue
		}
		links, err := p.attach(lib.Path)
		if err != nil {
			p.log.Debug("TLS sampler skipped a library", "path", lib.MapsPath, "error", err)
			p.attached[lib.Key] = &attachment{path: lib.MapsPath} // remember it so it is not retried every scan
			continue
		}
		p.attached[lib.Key] = &attachment{path: lib.MapsPath, links: links}
		added = append(added, lib.MapsPath)
	}
	return added, nil
}

// attach installs the uprobes on one library file. A write path and a read path
// are both required, and an entry probe whose return probe cannot attach is
// removed again (it would only fill the argument map).
func (p *Prober) attach(path string) ([]link.Link, error) {
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}
	var links []link.Link
	closeAll := func() {
		for _, l := range links {
			_ = l.Close()
		}
	}
	var sawWrite, sawRead bool
	pendingEntry := map[string]link.Link{}
	for _, pr := range probes {
		prog := p.coll.Programs[pr.prog]
		if prog == nil {
			closeAll()
			return nil, fmt.Errorf("program %s missing from object", pr.prog)
		}
		var l link.Link
		if pr.ret {
			if _, ok := pendingEntry[pr.sym]; !ok {
				continue // no entry probe to pair with: a return probe alone finds no arguments
			}
			l, err = ex.Uretprobe(pr.sym, prog, nil)
		} else {
			l, err = ex.Uprobe(pr.sym, prog, nil)
		}
		if err != nil {
			if pr.ret { // the entry probe alone is useless
				if e, ok := pendingEntry[pr.sym]; ok {
					_ = e.Close()
					delete(pendingEntry, pr.sym)
					links = removeLink(links, e)
				}
			}
			continue
		}
		links = append(links, l)
		switch {
		case !pr.ret && (pr.sym == "SSL_write" || pr.sym == "SSL_write_ex"):
			sawWrite = true
		case !pr.ret:
			pendingEntry[pr.sym] = l
		case pr.ret:
			delete(pendingEntry, pr.sym)
			sawRead = true
		}
	}
	// An entry probe still pending never got its return probe: drop it.
	for _, e := range pendingEntry {
		_ = e.Close()
		links = removeLink(links, e)
	}
	if !sawWrite || !sawRead {
		closeAll()
		return nil, fmt.Errorf("library lacks the SSL_write/SSL_read symbols (write=%v read=%v)", sawWrite, sawRead)
	}
	return links, nil
}

func removeLink(ls []link.Link, x link.Link) []link.Link {
	out := ls[:0]
	for _, l := range ls {
		if l != x {
			out = append(out, l)
		}
	}
	return out
}

// Libraries lists the library paths currently instrumented, sorted.
func (p *Prober) Libraries() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, a := range p.attached {
		if len(a.links) > 0 {
			out = append(out, a.path)
		}
	}
	sort.Strings(out)
	return out
}

// Run reads events until ctx is done, calling fn for each. Data is a view valid
// only during the call. Blocks; run it in its own goroutine.
func (p *Prober) Run(ctx context.Context, fn func(Event)) {
	rd, err := ringbuf.NewReader(p.coll.Maps["ssl_events"])
	if err != nil {
		p.log.Warn("open ssl_events ring buffer", "error", err)
		return
	}
	defer rd.Close()
	go func() { <-ctx.Done(); _ = rd.Close() }()
	for {
		rec, err := rd.Read()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, ringbuf.ErrClosed) {
				p.log.Warn("read ssl_events", "error", err)
			}
			return
		}
		ev, err := DecodeEvent(rec.RawSample)
		if err != nil {
			continue
		}
		fn(ev)
	}
}

// KernelStats reads the in-kernel counters, summed across CPUs.
func (p *Prober) KernelStats() (KernelStats, error) {
	m := p.coll.Maps["ssl_stats"]
	if m == nil {
		return KernelStats{}, errors.New("map ssl_stats missing")
	}
	var out KernelStats
	for _, f := range []struct {
		dst  *uint64
		slot uint32
	}{{&out.Eligible, 0}, {&out.Emitted, 1}, {&out.RateLimited, 2}, {&out.RingbufFull, 3}, {&out.ReadFail, 4}, {&out.CommFiltered, 5}} {
		var per []uint64
		if err := m.Lookup(f.slot, &per); err != nil {
			return KernelStats{}, fmt.Errorf("read ssl_stats[%d]: %w", f.slot, err)
		}
		for _, v := range per {
			*f.dst += v
		}
	}
	return out, nil
}

// ProgramStats reports total runs and time across the sampler's programs, from
// the kernel's BPF accounting (zero unless run-time statistics are enabled).
func (p *Prober) ProgramStats() (runs uint64, spent time.Duration, err error) {
	if p == nil || p.coll == nil {
		return 0, 0, errors.New("prober is closed")
	}
	for _, pr := range probes {
		st, err := p.coll.Programs[pr.prog].Stats()
		if err != nil {
			return 0, 0, err
		}
		runs += st.RunCount
		spent += st.Runtime
	}
	return runs, spent, nil
}

// Close detaches every probe and frees the maps.
func (p *Prober) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for _, a := range p.attached {
		for _, l := range a.links {
			errs = append(errs, l.Close())
		}
	}
	p.attached = map[string]*attachment{}
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
	}
	return errors.Join(errs...)
}
