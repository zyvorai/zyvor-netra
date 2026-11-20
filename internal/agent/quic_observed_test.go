// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
)

func TestDecodeQUICObservedABI(t *testing.T) {
	// Literal little-endian bytes independently check the C map ABI offsets:
	// cgroup_id[0:8], family[8], pad[9:12], remote_addr[12:28],
	// remote_port[28:30], pad2[30:32].
	var k [32]byte
	k[0] = 0x2a // cgroup_id = 42
	k[8] = 4    // family = IPv4
	copy(k[12:16], []byte{8, 8, 8, 8})
	k[28] = 0x1bb & 0xff // remote_port low byte (443 stored little-endian by native.Uint16)
	k[29] = 0x1bb >> 8

	var v [24]byte
	v[0] = 100 // packets
	v[8] = 60  // long_header_packets
	v[16] = 7  // last_ns

	got := decodeQUICObserved(k, v)
	if got.CgroupID != 42 || got.Family != "IPv4" || got.RemoteIP != "8.8.8.8" || got.RemotePort != 443 {
		t.Fatalf("%+v", got)
	}
	if got.Packets != 100 || got.LongHeaderPackets != 60 || got.LastSeenNS != 7 {
		t.Fatalf("%+v", got)
	}
}

func TestDecodeQUICObservedABIv6(t *testing.T) {
	var k [32]byte
	k[8] = 6 // family = IPv6
	copy(k[12:28], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	var v [24]byte
	got := decodeQUICObserved(k, v)
	if got.Family != "IPv6" || got.RemoteIP != "2001:db8::1" {
		t.Fatalf("%+v", got)
	}
}

func TestQUICObservedUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	rows, err := a.readQUICObserved()
	if err == nil || rows != nil {
		t.Fatalf("expected an error and nil rows for a missing map, got %v %v", rows, err)
	}
}

func TestEnrichQUICObservedSkipsZeroCgroup(t *testing.T) {
	a := &Agent{}
	st := models.QUICObservedStat{CgroupID: 0}
	a.enrichQUICObserved(&st)
	if st.Namespace != "" || st.WorkloadName != "" {
		t.Fatalf("expected no enrichment for cgroup_id=0, got %+v", st)
	}
}
