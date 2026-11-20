// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
)

// buildEvent lays out a record exactly as struct l7s_event in the BPF object.
func buildEvent(family byte, egress bool, proto Protocol, toServer bool, sport, dport uint16, src, dst net.IP, payload []byte) []byte {
	b := make([]byte, EventSize)
	binary.LittleEndian.PutUint64(b[0:], 123456789)
	binary.LittleEndian.PutUint64(b[8:], 4242)
	b[16] = family
	if !egress {
		b[17] = 1
	}
	b[18] = byte(proto)
	if toServer {
		b[19] = 1
	}
	binary.LittleEndian.PutUint16(b[20:], sport)
	binary.LittleEndian.PutUint16(b[22:], dport)
	if family == 4 {
		copy(b[24:28], src.To4())
		copy(b[40:44], dst.To4())
	} else {
		copy(b[24:40], src.To16())
		copy(b[40:56], dst.To16())
	}
	binary.LittleEndian.PutUint16(b[56:], uint16(len(payload)))
	copy(b[headerLen:], payload)
	return b
}

func TestEventSizeMatchesTheCStruct(t *testing.T) {
	// struct l7s_event is packed: 8+8 + 4x u8 + 2x u16 + 2x16 + u16 + u16 + 128.
	if headerLen != 8+8+4+2+2+16+16+2+2 || EventSize != 188 {
		t.Fatalf("headerLen=%d EventSize=%d: out of step with bpf/netra_l7sample.c", headerLen, EventSize)
	}
}

func TestDecodeEventV4AndV6(t *testing.T) {
	v4 := buildEvent(4, true, ProtoRedis, true, 41000, 6379, net.ParseIP("10.1.2.3"), net.ParseIP("10.9.8.7"), []byte("*1\r\n$4\r\nPING\r\n"))
	s, err := DecodeEvent(v4)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Egress || s.Proto != ProtoRedis || !s.ToServer || s.SrcPort != 41000 || s.DstPort != 6379 ||
		s.Src.String() != "10.1.2.3" || s.Dst.String() != "10.9.8.7" || s.CgroupID != 4242 || string(s.Data) != "*1\r\n$4\r\nPING\r\n" {
		t.Fatalf("v4 = %+v", s)
	}
	v6 := buildEvent(6, false, ProtoPostgres, false, 5432, 50000, net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), []byte("Z\x00\x00\x00\x05I"))
	s, err = DecodeEvent(v6)
	if err != nil || s.Egress || s.ToServer || s.Src.String() != "fd00::1" || s.Dst.String() != "fd00::2" || s.Proto != ProtoPostgres {
		t.Fatalf("v6 = %+v err=%v", s, err)
	}
}

func TestDecodeEventRejectsMalformedRecords(t *testing.T) {
	good := buildEvent(4, true, ProtoRedis, true, 1, 2, net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), []byte("x"))
	if _, err := DecodeEvent(good[:EventSize-1]); err == nil {
		t.Error("a short record was accepted")
	}
	for name, mutate := range map[string]func([]byte){
		"zero length": func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 0) },
		"huge length": func(b []byte) { binary.LittleEndian.PutUint16(b[56:], CopyMax+1) },
		"bad family":  func(b []byte) { b[16] = 9 },
	} {
		b := append([]byte(nil), good...)
		mutate(b)
		if _, err := DecodeEvent(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// sample is a server-side view: a request arrives (ingress) and its reply leaves
// (egress), so both fall in the "served" role.
func sample(p Protocol, toServer bool, payload string) Sample {
	return Sample{Proto: p, ToServer: toServer, Egress: !toServer, Data: []byte(payload)}
}

func TestRoleSeparatesWhatWasServedFromWhatWasIssued(t *testing.T) {
	for _, c := range []struct {
		toServer, egress bool
		want             string
	}{
		{true, false, RoleServed},  // a request arriving at a service on this node
		{false, true, RoleServed},  // its response leaving
		{true, true, RoleIssued},   // a request this node's workload sends
		{false, false, RoleIssued}, // the response it gets back
	} {
		if got := RoleOf(Sample{ToServer: c.toServer, Egress: c.egress}); got != c.want {
			t.Errorf("toServer=%v egress=%v => %s, want %s", c.toServer, c.egress, got, c.want)
		}
	}
}

// The same GET seen leaving the client and arriving at the server must not be
// counted as two requests in one number.
func TestARequestSeenOnBothSidesIsCountedOncePerRole(t *testing.T) {
	c := NewCounters()
	get := []byte("*2\r\n$3\r\nGET\r\n$1\r\nk\r\n")
	for i := 0; i < 5; i++ {
		c.Observe(Sample{Proto: ProtoRedis, ToServer: true, Egress: true, Data: get})  // client egress
		c.Observe(Sample{Proto: ProtoRedis, ToServer: true, Egress: false, Data: get}) // server ingress
	}
	byRole := map[string]uint64{}
	for _, p := range c.Snapshot().Protocols {
		byRole[p.Role] += p.Requests
	}
	if byRole[RoleServed] != 5 || byRole[RoleIssued] != 5 || len(byRole) != 2 {
		t.Fatalf("requests by role = %v, want 5 served and 5 issued, never 10 in one number", byRole)
	}
}

func TestCountersAggregateRequestsResponsesAndErrors(t *testing.T) {
	c := NewCounters()
	for i := 0; i < 5; i++ {
		c.Observe(sample(ProtoRedis, true, "*2\r\n$3\r\nGET\r\n$1\r\nk\r\n"))
	}
	for i := 0; i < 2; i++ {
		c.Observe(sample(ProtoRedis, true, "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"))
	}
	for i := 0; i < 6; i++ {
		c.Observe(sample(ProtoRedis, false, "+OK\r\n"))
	}
	c.Observe(sample(ProtoRedis, false, "-ERR bad\r\n"))
	c.Observe(sample(ProtoRedis, true, "\x00\x01garbage")) // not classifiable
	s := c.Snapshot()
	if s.Seen != 15 || s.Classified != 14 {
		t.Fatalf("seen=%d classified=%d, want 15 and 14", s.Seen, s.Classified)
	}
	if len(s.Protocols) != 1 {
		t.Fatalf("protocols = %+v", s.Protocols)
	}
	p := s.Protocols[0]
	if p.Role != RoleServed {
		t.Fatalf("role = %q", p.Role)
	}
	if p.Protocol != "redis" || p.Requests != 7 || p.Responses != 7 || p.Errors != 1 {
		t.Fatalf("redis = %+v", p)
	}
	if len(p.Ops) != 2 || p.Ops[0] != (OpCount{"GET", 5}) || p.Ops[1] != (OpCount{"SET", 2}) {
		t.Fatalf("ops = %+v, want GET 5 then SET 2", p.Ops)
	}
	var foundErr bool
	for _, cc := range p.Codes {
		if cc.Code == "ERR" && cc.Status == "error" && cc.Count == 1 {
			foundErr = true
		}
	}
	if !foundErr {
		t.Fatalf("codes = %+v, want ERR/error 1", p.Codes)
	}
}

func TestCountersTrackHTTPHostsAndUndecodableHTTP2(t *testing.T) {
	c := NewCounters()
	for i := 0; i < 3; i++ {
		c.Observe(sample(ProtoHTTP1, true, "GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n"))
	}
	c.Observe(sample(ProtoHTTP1, true, "POST /y HTTP/1.1\r\nHost: b.example\r\n\r\n"))
	enc, buf := newEnc()
	first := hpackBlock(enc, buf, grpcReqFields("/p.S/M")...)
	second := hpackBlock(enc, buf, grpcReqFields("/p.S/M")...)
	c.Observe(Sample{Proto: ProtoHTTP2, ToServer: true, Data: h2Frame(0x1, 0x4, 1, first)})
	c.Observe(Sample{Proto: ProtoHTTP2, ToServer: true, Data: h2Frame(0x1, 0x4, 3, second)})
	s := c.Snapshot()
	if len(s.Hosts) < 2 || s.Hosts[0] != (HostCount{RoleServed, "a.example", "GET", 3}) {
		t.Fatalf("hosts = %+v", s.Hosts)
	}
	var h2 ProtoStats
	for _, p := range s.Protocols {
		if p.Protocol == "http2" {
			h2 = p
		}
	}
	if h2.Requests != 2 || h2.GRPC != 1 || h2.Undecodable != 1 {
		t.Fatalf("http2 = %+v, want 2 requests, 1 gRPC, 1 undecodable", h2)
	}
}

func TestCountersAreBoundedNoMatterWhatIsObserved(t *testing.T) {
	c := NewCounters()
	// Adversarial: many distinct hosts and many distinct gRPC methods.
	for i := 0; i < 5000; i++ {
		c.Observe(sample(ProtoHTTP1, true, fmt.Sprintf("GET / HTTP/1.1\r\nHost: h%d.example\r\n\r\n", i)))
	}
	for i := 0; i < 2000; i++ {
		enc, buf := newEnc()
		blk := hpackBlock(enc, buf, grpcReqFields(fmt.Sprintf("/pkg.Svc/Method%d", i))...)
		c.Observe(Sample{Proto: ProtoHTTP2, ToServer: true, Data: h2Frame(0x1, 0x4, 1, blk)})
	}
	if len(c.hosts) > maxHostKeys || len(c.ops) > maxOpKeys {
		t.Fatalf("tables grew past their caps: hosts=%d ops=%d", len(c.hosts), len(c.ops))
	}
	s := c.Snapshot()
	if s.Overflow == 0 || s.HostsOthers == 0 {
		t.Fatalf("overflow was not accounted for: %+v", s)
	}
	if len(s.Hosts) > topHosts {
		t.Fatalf("%d hosts in a snapshot, cap %d", len(s.Hosts), topHosts)
	}
	for _, p := range s.Protocols {
		if len(p.Ops) > topOpsPerRow+1 {
			t.Fatalf("%s lists %d ops", p.Protocol, len(p.Ops))
		}
	}
}

func TestCountersAreSafeForConcurrentUse(t *testing.T) {
	c := NewCounters()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				c.Observe(sample(ProtoRedis, true, "*1\r\n$4\r\nPING\r\n"))
				if i%200 == 0 {
					_ = c.Snapshot()
				}
			}
		}()
	}
	wg.Wait()
	if s := c.Snapshot(); s.Seen != 16000 || s.Protocols[0].Requests != 16000 {
		t.Fatalf("lost updates: %+v", s)
	}
}

// The host table has the same double-sighting problem as the protocol table: one
// request is seen leaving its client and arriving at its server. Counting both into
// one (host, method) number reported 30 requests for 15 real ones on a live run.
func TestHostCountsAreKeptPerRoleSoARequestIsNotCountedTwice(t *testing.T) {
	c := NewCounters()
	req := []byte("GET /x HTTP/1.1\r\nHost: shop.example\r\n\r\n")
	for i := 0; i < 15; i++ {
		c.Observe(Sample{Proto: ProtoHTTP1, ToServer: true, Egress: true, Data: req})  // the client's egress
		c.Observe(Sample{Proto: ProtoHTTP1, ToServer: true, Egress: false, Data: req}) // the server's ingress
	}
	byRole := map[string]uint64{}
	for _, h := range c.Snapshot().Hosts {
		if h.Host == "shop.example" && h.Op == "GET" {
			byRole[h.Role] += h.Count
		}
	}
	if byRole[RoleIssued] != 15 || byRole[RoleServed] != 15 || len(byRole) != 2 {
		t.Fatalf("host counts by role = %v, want 15 issued and 15 served, never 30 in one row", byRole)
	}
}
