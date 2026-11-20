// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package listenq samples the accept-queue depth of every TCP listener on the
// host, and the number of half-open (SYN_RECV) connections waiting on each.
//
// The kernel already counts *that* a listen queue overflowed
// (TcpExt.ListenOverflows, ListenDrops); it does not say which listener, or how
// close the others are to it. inet_diag does: for a LISTEN socket it reports the
// current accept-queue length and the configured backlog. That needs no BPF, no
// BTF and no root, and works on every kernel.
package listenq

import (
	"sort"
	"sync"
)

// Listener is one listening TCP socket at one instant.
type Listener struct {
	Family string `json:"family"` // ipv4 | ipv6
	Addr   string `json:"addr"`   // bound address; 0.0.0.0 / :: for a wildcard
	Port   uint16 `json:"port"`
	// Queue is connections that finished the handshake and wait for accept();
	// Max is the listen() backlog, which the kernel enforces as "full when
	// Queue > Max", so the queue holds Max+1 entries.
	Queue uint32 `json:"queue"`
	Max   uint32 `json:"max"`
	// SynRecv is half-open connections (SYN received, final ACK not yet).
	SynRecv uint32 `json:"synRecv,omitempty"`
}

// Full reports whether new connections are being refused right now
// (sk_acceptq_is_full: queue > backlog).
func (l Listener) Full() bool { return l.Queue > l.Max }

// Pct is how full the accept queue is, 0..100, against its real capacity of
// Max+1 entries, so that Pct == 100 exactly when Full().
func (l Listener) Pct() int {
	p := int(uint64(l.Queue) * 100 / (uint64(l.Max) + 1))
	if p > 100 {
		p = 100
	}
	return p
}

// SaturatedPct is the fill level at and above which a listener counts as
// saturated: close enough to full that a modest burst overflows it.
const SaturatedPct = 80

// Saturated reports Pct() >= SaturatedPct.
func (l Listener) Saturated() bool { return l.Pct() >= SaturatedPct }

// Buckets are the fill-level histogram bins, in order.
var Buckets = []string{"empty", "le_25", "le_50", "le_75", "lt_100", "full"}

func bucketOf(l Listener) int {
	switch {
	case l.Queue == 0:
		return 0
	case l.Full():
		return 5
	}
	switch p := l.Pct(); {
	case p <= 25:
		return 1
	case p <= 50:
		return 2
	case p <= 75:
		return 3
	}
	return 4
}

// Entry is a listener with the highest queue depth seen since sampling began.
type Entry struct {
	Listener
	// Peak is the deepest accept queue observed at a sample since this listener
	// was first seen. Sampling is periodic: a burst that rose and drained
	// between two samples is not seen.
	Peak    uint32 `json:"peak"`
	PeakPct int    `json:"peakPct"`
}

// Snapshot is the cumulative view at one sample.
type Snapshot struct {
	Listeners int `json:"listeners"` // listening sockets right now
	Full      int `json:"full"`      // refusing connections right now
	Saturated int `json:"saturated"` // at or above SaturatedPct right now (includes Full)
	// SynRecv is half-open connections across all listeners right now.
	SynRecv uint64 `json:"synRecv"`
	// Samples is how many samples the histogram holds; Buckets[b] is the
	// number of (listener, sample) pairs that fell in bin b. Idle listeners
	// dominate "empty": read the other bins.
	Samples uint64            `json:"samples"`
	Buckets map[string]uint64 `json:"buckets"`
	// Top is the listeners that are, or have been, under pressure, deepest
	// first; idle listeners are omitted.
	Top []Entry `json:"top,omitempty"`
}

type key struct {
	family, addr string
	port         uint16
}

// maxTracked bounds the peak table; a host has tens of listeners, so reaching
// it means something is churning ports and old entries are simply dropped.
const maxTracked = 4096

// Sampler accumulates peaks and the fill histogram across samples. The zero
// value samples the local kernel.
type Sampler struct {
	// Dump returns the current listeners. Nil means the local kernel
	// (inet_diag); tests inject a fake.
	Dump func() ([]Listener, error)

	mu      sync.Mutex
	samples uint64
	buckets [6]uint64
	peaks   map[key]uint32
}

// Sample reads the listeners once, folds them into the histogram and peaks, and
// returns the snapshot with at most top entries.
func (s *Sampler) Sample(top int) (*Snapshot, error) {
	dump := s.Dump
	if dump == nil {
		dump = Dump
	}
	ls, err := dump()
	if err != nil {
		return nil, err
	}
	if top <= 0 {
		top = 20
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peaks == nil {
		s.peaks = map[key]uint32{}
	}
	snap := &Snapshot{Listeners: len(ls), Buckets: map[string]uint64{}}
	live := make(map[key]bool, len(ls))
	var entries []Entry
	for _, l := range ls {
		k := key{l.Family, l.Addr, l.Port}
		live[k] = true
		s.buckets[bucketOf(l)]++
		if l.Full() {
			snap.Full++
		}
		if l.Saturated() {
			snap.Saturated++
		}
		snap.SynRecv += uint64(l.SynRecv)
		if l.Queue > s.peaks[k] {
			s.peaks[k] = l.Queue
		}
		if p := s.peaks[k]; p > 0 || l.SynRecv > 0 {
			e := Entry{Listener: l, Peak: p}
			e.PeakPct = Listener{Queue: p, Max: l.Max}.Pct()
			entries = append(entries, e)
		}
	}
	// A listener that has gone away takes its peak with it.
	for k := range s.peaks {
		if !live[k] {
			delete(s.peaks, k)
		}
	}
	for len(s.peaks) > maxTracked {
		for k := range s.peaks {
			delete(s.peaks, k)
			break
		}
	}
	s.samples++
	snap.Samples = s.samples
	for i, name := range Buckets {
		snap.Buckets[name] = s.buckets[i]
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Pct() != b.Pct() {
			return a.Pct() > b.Pct()
		}
		if a.Queue != b.Queue {
			return a.Queue > b.Queue
		}
		if a.PeakPct != b.PeakPct {
			return a.PeakPct > b.PeakPct
		}
		if a.SynRecv != b.SynRecv {
			return a.SynRecv > b.SynRecv
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Addr < b.Addr
	})
	if len(entries) > top {
		entries = entries[:top]
	}
	snap.Top = entries
	return snap, nil
}
