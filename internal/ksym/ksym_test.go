// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package ksym

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const table = `ffffffff81000000 T _stext
ffffffff81001000 T tcp_v4_rcv
ffffffff81002000 t nf_hook_slow
ffffffff81003000 d some_data_symbol
ffffffff81004000 T ip_rcv [ipv4mod]
ffffffff81005000 W weak_fn
`

func resolver(counter *atomic.Int32, text string) *Resolver {
	return &Resolver{Open: func() (io.ReadCloser, error) {
		counter.Add(1)
		return io.NopCloser(strings.NewReader(text)), nil
	}}
}

func TestResolvesToTheContainingTextSymbol(t *testing.T) {
	var n atomic.Int32
	r := resolver(&n, table)
	got := r.Resolve([]uint64{0xffffffff81001abc, 0xffffffff81002000, 0xffffffff81004010, 0xffffffff81005ff0})
	for addr, want := range map[uint64]string{
		0xffffffff81001abc: "tcp_v4_rcv",
		0xffffffff81002000: "nf_hook_slow",
		0xffffffff81004010: "ip_rcv [ipv4mod]",
		0xffffffff81005ff0: "weak_fn",
	} {
		if got[addr] != want {
			t.Errorf("%#x = %q, want %q", addr, got[addr], want)
		}
	}
}

func TestDataSymbolsAreNotTextAndAddressesBelowTheFirstAreUnresolved(t *testing.T) {
	var n atomic.Int32
	r := resolver(&n, table)
	got := r.Resolve([]uint64{0xffffffff81003100, 0xffffffff80000000})
	// 0x…3100 is after a data symbol: it must be attributed to the previous
	// *text* symbol, never to the data one.
	if got[0xffffffff81003100] != "nf_hook_slow" {
		t.Errorf("got %q", got[0xffffffff81003100])
	}
	if got[0xffffffff80000000] != "0xffffffff80000000" {
		t.Errorf("below the first symbol should be unresolved, got %q", got[0xffffffff80000000])
	}
}

func TestFarPastTheLastSymbolIsNotBlamedOnIt(t *testing.T) {
	var n atomic.Int32
	got := resolver(&n, table).Resolve([]uint64{0xffffffff81005000 + maxSpan + 1})
	for _, v := range got {
		if strings.HasPrefix(v, "weak_fn") {
			t.Fatalf("attributed to %q", v)
		}
	}
}

func TestHiddenAddressesLeaveEveryAddressUnresolved(t *testing.T) {
	var n atomic.Int32
	hidden := "0000000000000000 T tcp_v4_rcv\n0000000000000000 T nf_hook_slow\n"
	got := resolver(&n, hidden).Resolve([]uint64{0xffffffff81001abc})
	if got[0xffffffff81001abc] != "0xffffffff81001abc" {
		t.Errorf("got %q", got[0xffffffff81001abc])
	}
}

func TestTheTableIsReadOnlyForAddressesNotYetSeen(t *testing.T) {
	var n atomic.Int32
	r := resolver(&n, table)
	clock := time.Unix(1000, 0)
	r.now = func() time.Time { return clock }
	r.Resolve([]uint64{0xffffffff81001abc})
	r.Resolve([]uint64{0xffffffff81001abc, 0xffffffff81001abc})
	if n.Load() != 1 {
		t.Fatalf("kallsyms read %d times, want 1", n.Load())
	}
	clock = clock.Add(keepTable)
	r.Resolve([]uint64{0xffffffff81002abc})
	if n.Load() != 2 {
		t.Fatalf("a new address should trigger one more read, got %d", n.Load())
	}
}

func TestNewAddressesSoonAfterAReadUseTheKeptTable(t *testing.T) {
	var n atomic.Int32
	r := resolver(&n, table)
	clock := time.Unix(1000, 0)
	r.now = func() time.Time { return clock }
	r.Resolve([]uint64{0xffffffff81001abc})
	clock = clock.Add(keepTable - time.Second)
	got := r.Resolve([]uint64{0xffffffff81001abc, 0xffffffff81002abc})
	if n.Load() != 1 {
		t.Fatalf("kallsyms read %d times inside the window, want 1", n.Load())
	}
	if got[0xffffffff81002abc] != "nf_hook_slow" {
		t.Fatalf("a new address is named from the kept table, got %q", got[0xffffffff81002abc])
	}
	clock = clock.Add(time.Second)
	if got := r.Resolve([]uint64{0xffffffff81002abc}); got[0xffffffff81002abc] != "nf_hook_slow" {
		t.Fatalf("got %q", got[0xffffffff81002abc])
	}
	if n.Load() != 2 {
		t.Fatalf("a name from a kept table is provisional and re-read once it expires; reads = %d, want 2", n.Load())
	}
	r.Resolve([]uint64{0xffffffff81002abc})
	if n.Load() != 2 {
		t.Fatalf("after a fresh read the name is cached; reads = %d, want 2", n.Load())
	}
}

func TestUnreadableKallsymsStillAnswersEveryAddress(t *testing.T) {
	r := &Resolver{Open: func() (io.ReadCloser, error) { return nil, io.ErrClosedPipe }}
	got := r.Resolve([]uint64{1, 2})
	if len(got) != 2 || got[1] != "0x1" {
		t.Fatalf("got %v", got)
	}
}
