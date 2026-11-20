// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
)

func TestDecodeUDPFlowHealthABI(t *testing.T) {
	// Literal little-endian bytes independently check the C map ABI offsets
	// (cgroup_id[0:8], family[8], pad[9:12], local_ip4[12:16], remote_ip4[16:20],
	// local_ip6[20:36], remote_ip6[36:52], local_port[52:54], remote_port[54:56]).
	var k [56]byte
	k[0] = 0x2a // cgroup_id = 42
	k[8] = 4    // family = IPv4
	copy(k[12:16], []byte{10, 0, 0, 1})
	copy(k[16:20], []byte{8, 8, 8, 8})
	k[52] = 0x35 // local_port low byte
	k[54] = 0x35 // remote_port low byte

	var v [24]byte
	v[0] = 5   // packets
	v[8] = 200 // bytes
	v[16] = 9  // last_ns

	got := decodeUDPFlowHealth(k, v)
	if got.CgroupID != 42 || got.Family != "IPv4" || got.LocalIP != "10.0.0.1" || got.RemoteIP != "8.8.8.8" {
		t.Fatalf("%+v", got)
	}
	if got.LocalPort != 0x35 || got.RemotePort != 0x35 || got.Packets != 5 || got.Bytes != 200 || got.LastSeenNS != 9 {
		t.Fatalf("%+v", got)
	}
}

func TestUDPFlowHealthUnavailableWhenMapMissing(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	rows, err := a.readUDPFlowHealth()
	if err == nil || rows != nil {
		t.Fatalf("expected an error and nil rows for a missing map, got %v %v", rows, err)
	}
}

func TestEnrichUDPFlowHealthSkipsZeroCgroup(t *testing.T) {
	a := &Agent{}
	st := models.UDPFlowHealthStat{CgroupID: 0}
	a.enrichUDPFlowHealth(&st)
	if st.Namespace != "" || st.WorkloadName != "" {
		t.Fatalf("expected no enrichment for cgroup_id=0, got %+v", st)
	}
}
