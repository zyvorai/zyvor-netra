// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import (
	"sort"
	"sync"
)

// Bounds. Every label is already bounded by the parsers; these caps make the
// memory and report size bounded even if that ever regressed.
const (
	maxOpKeys    = 512 // distinct (protocol, kind, op, status, code) tuples
	maxHostKeys  = 200 // distinct (host, method) pairs
	topOpsPerRow = 30  // ops listed per protocol in a snapshot
	topHosts     = 50
)

// Role says which side of the conversation this node observed. A request is seen
// twice on the wire: leaving the client (egress) and arriving at the server
// (ingress). Counting both would double every request, so they are kept apart:
// "served" is what this node's services handled (requests arriving, responses
// leaving) and "issued" is what its workloads asked of others (requests leaving,
// responses arriving). Sum a role across nodes, never the two roles together.
const (
	RoleServed = "served"
	RoleIssued = "issued"
)

// RoleOf reports the role a sample belongs to.
func RoleOf(s Sample) string {
	if s.ToServer == s.Egress { // request leaving, or response arriving
		return RoleIssued
	}
	return RoleServed
}

type opKey struct {
	role   string
	proto  Protocol
	kind   Kind
	op     string
	status Status
	code   string
	grpc   bool
}

type hostKey struct {
	role, host, op string
}

// Counters turns classified samples into cumulative, bounded counts. Safe for
// concurrent use.
type Counters struct {
	mu           sync.Mutex
	ops          map[opKey]uint64
	overflow     uint64 // observations dropped because a table was full
	hosts        map[hostKey]uint64
	hostOverflow uint64
	seen         uint64           // samples offered
	classified   uint64           // samples a parser recognised
	undecodable  map[opKey]uint64 // keyed by (role, protocol); other fields zero
}

func (c *Counters) undecodableFor(p Protocol, role string) uint64 {
	return c.undecodable[opKey{role: role, proto: p}]
}

// NewCounters returns empty Counters.
func NewCounters() *Counters {
	return &Counters{ops: map[opKey]uint64{}, hosts: map[hostKey]uint64{}, undecodable: map[opKey]uint64{}}
}

// Observe classifies one sample and counts it. The payload is not retained.
func (c *Counters) Observe(s Sample) {
	o, ok := Parse(s.Proto, s.ToServer, s.Data)
	c.ObserveObs(o, ok, RoleOf(s))
}

// ObserveObs counts an already-classified observation in the given role, for
// sources that classify plaintext themselves (the TLS uprobe sampler). ok=false
// counts the sample as seen but unclassified.
func (c *Counters) ObserveObs(o Obs, ok bool, role string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen++
	if !ok {
		return
	}
	c.classified++
	if o.Op == "undecodable_headers" {
		c.undecodable[opKey{role: role, proto: o.Proto}]++
	}
	k := opKey{role, o.Proto, o.Kind, o.Op, o.Status, o.Code, o.GRPC}
	if _, exists := c.ops[k]; !exists && len(c.ops) >= maxOpKeys {
		c.overflow++
	} else {
		c.ops[k]++
	}
	if o.Host != "" && o.Kind == KindRequest {
		hk := hostKey{role, o.Host, o.Op}
		if _, exists := c.hosts[hk]; !exists && len(c.hosts) >= maxHostKeys {
			c.hostOverflow++
		} else {
			c.hosts[hk]++
		}
	}
}

// OpCount is one operation and its count.
type OpCount struct {
	Op    string `json:"op"`
	Count uint64 `json:"count"`
}

// CodeCount is a response outcome and its count.
type CodeCount struct {
	Code   string `json:"code"`
	Status string `json:"status,omitempty"`
	Count  uint64 `json:"count"`
}

// ProtoStats is one protocol's counts in one role.
type ProtoStats struct {
	Protocol    string      `json:"protocol"`
	Role        string      `json:"role"`
	Requests    uint64      `json:"requests"`
	Responses   uint64      `json:"responses"`
	Errors      uint64      `json:"errors"`
	Undecodable uint64      `json:"undecodable,omitempty"`
	GRPC        uint64      `json:"grpc,omitempty"` // requests that were gRPC
	Ops         []OpCount   `json:"ops,omitempty"`
	Codes       []CodeCount `json:"codes,omitempty"`
}

// HostCount is a bounded (role, host, method) request count. The role keeps a
// request seen leaving its client and arriving at its server from being counted
// twice in one number.
type HostCount struct {
	Role  string `json:"role"`
	Host  string `json:"host"`
	Op    string `json:"op"`
	Count uint64 `json:"count"`
}

// Snapshot is the cumulative view.
type Snapshot struct {
	Seen        uint64       `json:"seen"`
	Classified  uint64       `json:"classified"`
	Overflow    uint64       `json:"overflow,omitempty"`
	Protocols   []ProtoStats `json:"protocols,omitempty"`
	Hosts       []HostCount  `json:"hosts,omitempty"`
	HostsOthers uint64       `json:"hostsOther,omitempty"`
}

// Snapshot returns the counts so far. Ops per protocol are the busiest
// topOpsPerRow, with the remainder folded into "OTHER".
func (c *Counters) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := Snapshot{Seen: c.seen, Classified: c.classified, Overflow: c.overflow, HostsOthers: c.hostOverflow}
	type pr struct {
		proto Protocol
		role  string
	}
	byProto := map[pr]*ProtoStats{}
	ops := map[pr]map[string]uint64{}
	codes := map[pr]map[CodeCount]uint64{}
	for k, n := range c.ops {
		key := pr{k.proto, k.role}
		ps := byProto[key]
		if ps == nil {
			ps = &ProtoStats{Protocol: k.proto.String(), Role: k.role, Undecodable: c.undecodableFor(k.proto, k.role)}
			byProto[key] = ps
			ops[key] = map[string]uint64{}
			codes[key] = map[CodeCount]uint64{}
		}
		switch k.kind {
		case KindRequest:
			ps.Requests += n
			if k.op != "" {
				ops[key][k.op] += n
			}
			if k.grpc {
				ps.GRPC += n
			}
		case KindResponse:
			ps.Responses += n
			if k.status == StatusError {
				ps.Errors += n
			}
			if k.code != "" {
				codes[key][CodeCount{Code: k.code, Status: k.status.String()}] += n
			}
		}
	}
	for p, ps := range byProto {
		var list []OpCount
		for op, n := range ops[p] {
			list = append(list, OpCount{op, n})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count != list[j].Count {
				return list[i].Count > list[j].Count
			}
			return list[i].Op < list[j].Op
		})
		if len(list) > topOpsPerRow {
			var rest uint64
			for _, x := range list[topOpsPerRow:] {
				rest += x.Count
			}
			list = append(list[:topOpsPerRow], OpCount{"OTHER", rest})
		}
		ps.Ops = list
		for cc, n := range codes[p] {
			cc.Count = n
			ps.Codes = append(ps.Codes, cc)
		}
		sort.Slice(ps.Codes, func(i, j int) bool {
			if ps.Codes[i].Count != ps.Codes[j].Count {
				return ps.Codes[i].Count > ps.Codes[j].Count
			}
			return ps.Codes[i].Code < ps.Codes[j].Code
		})
		out.Protocols = append(out.Protocols, *ps)
	}
	sort.Slice(out.Protocols, func(i, j int) bool {
		if out.Protocols[i].Protocol != out.Protocols[j].Protocol {
			return out.Protocols[i].Protocol < out.Protocols[j].Protocol
		}
		return out.Protocols[i].Role < out.Protocols[j].Role
	})
	for hk, n := range c.hosts {
		out.Hosts = append(out.Hosts, HostCount{hk.role, hk.host, hk.op, n})
	}
	sort.Slice(out.Hosts, func(i, j int) bool {
		if out.Hosts[i].Count != out.Hosts[j].Count {
			return out.Hosts[i].Count > out.Hosts[j].Count
		}
		return out.Hosts[i].Role+out.Hosts[i].Host+out.Hosts[i].Op < out.Hosts[j].Role+out.Hosts[j].Host+out.Hosts[j].Op
	})
	if len(out.Hosts) > topHosts {
		out.Hosts = out.Hosts[:topHosts]
	}
	return out
}
