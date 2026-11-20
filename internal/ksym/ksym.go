// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package ksym resolves kernel text addresses to symbol names through
// /proc/kallsyms. A kernel drop event carries the address of the code that
// freed the packet; the name (e.g. tcp_v4_rcv, nf_hook_slow) is what makes it
// readable.
package ksym

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type symbol struct {
	addr uint64
	name string // module symbols carry a " [module]" suffix
}

// Resolver caches resolved addresses. The full table is read only when an
// address it has not seen appears, and is kept only briefly afterwards: a
// kernel has ~200k symbols and drop sites are a handful.
type Resolver struct {
	// Open returns the kallsyms stream. Nil means /proc/kallsyms.
	Open func() (io.ReadCloser, error)

	mu     sync.Mutex
	cache  map[uint64]string
	table  []symbol // kept for keepTable after a read, then released
	loaded time.Time
	now    func() time.Time // nil means time.Now
}

// keepTable is how long a read table answers new addresses before it is
// released. A read parses ~200k lines (~150 ms on a busy node); without this a
// host whose drop sites trickle in pays it on most snapshots.
const keepTable = 30 * time.Second

// Unresolved is returned for an address that has no symbol, or for every
// address when the kernel hides them (kernel.kptr_restrict, no CAP_SYSLOG).
func Unresolved(addr uint64) string { return fmt.Sprintf("0x%x", addr) }

// maxCache bounds the cache; drop locations are few, so hitting it means the
// input is not real addresses.
const maxCache = 4096

// Resolve names each address (symbol only, no offset). It always returns one
// entry per input address.
func (r *Resolver) Resolve(addrs []uint64) map[uint64]string {
	out := make(map[uint64]string, len(addrs))
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = map[uint64]string{}
	}
	var missing []uint64
	for _, a := range addrs {
		if n, ok := r.cache[a]; ok {
			out[a] = n
		} else if _, dup := out[a]; !dup {
			out[a] = ""
			missing = append(missing, a)
		}
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	if r.table != nil && now().Sub(r.loaded) >= keepTable {
		r.table = nil
	}
	if len(missing) == 0 {
		return out
	}
	// Names from a kept table are not cached: a module loaded since the read
	// is missing from it, so the next fresh read settles them.
	fresh := r.table == nil
	if fresh {
		r.table, _ = r.load()
		r.loaded = now()
	}
	for _, a := range missing {
		name := lookup(r.table, a)
		if name == "" {
			name = Unresolved(a)
		}
		out[a] = name
		if fresh && len(r.cache) < maxCache {
			r.cache[a] = name
		}
	}
	return out
}

func (r *Resolver) load() ([]symbol, error) {
	open := r.Open
	if open == nil {
		open = func() (io.ReadCloser, error) { return os.Open("/proc/kallsyms") }
	}
	f, err := open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parse(f)
}

// parse reads kallsyms lines `addr type name [module]`, keeping text symbols.
// Addresses of zero mean the kernel is hiding them; such a table is useless
// and yields no symbols.
func parse(rd io.Reader) ([]symbol, error) {
	var out []symbol
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		switch fields[1] {
		case "t", "T", "w", "W":
		default:
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		name := fields[2]
		if len(fields) > 3 && strings.HasPrefix(fields[3], "[") {
			name += " " + fields[3]
		}
		out = append(out, symbol{addr, name})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].addr < out[j].addr })
	return out, nil
}

// maxSpan is the farthest an address may be past the start of the symbol it is
// attributed to. kallsyms has no sizes, so without a bound an address past the
// end of the last text symbol would be blamed on it.
const maxSpan = 1 << 20

func lookup(table []symbol, addr uint64) string {
	i := sort.Search(len(table), func(i int) bool { return table[i].addr > addr })
	if i == 0 {
		return ""
	}
	s := table[i-1]
	if addr-s.addr > maxSpan {
		return ""
	}
	return s.name
}
