// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"encoding/json"
	"github.com/cilium/ebpf"
	"github.com/zyvorai/netra/internal/models"
	"net"
	"strings"
	"testing"
)

func TestDecodeICMPErrorABI(t *testing.T) {
	// Literal little-endian bytes independently check the C map ABI offsets.
	k := [8]byte{0x78, 0x56, 0x34, 0x12, 6, 2, 0, 1}
	v := [24]byte{7, 0, 0, 0, 1, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0}
	got := decodeICMPError(k, v)
	if got.InterfaceIndex != 0x12345678 || got.Family != "IPv6" || got.Type != 2 || got.Code != 0 || got.Direction != "ingress" || got.Hook != "tc" || got.Packets != 4294967303 || got.AdvertisedMTU != 1280 || got.LastSeenNS != 8589934601 {
		t.Fatalf("%+v", got)
	}
	b, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(b), `"advertisedMtu":1280`) {
		t.Fatal(string(b), err)
	}
}
func TestICMPOldObjectCompatibility(t *testing.T) {
	a := &Agent{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	rows, err := a.readICMPErrors()
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
}

func TestICMPInterfaceNamesRetainIndex(t *testing.T) {
	rows := []models.ICMPErrorStat{{InterfaceIndex: 2}, {InterfaceIndex: 99}, {InterfaceIndex: 0}}
	enrichICMPInterfaces(rows, []net.Interface{{Index: 2, Name: "eth0"}, {Index: 0, Name: "invalid"}})
	if rows[0].InterfaceName != "eth0" || rows[0].InterfaceIndex != 2 || rows[1].InterfaceName != "" || rows[1].InterfaceIndex != 99 || rows[2].InterfaceName != "" {
		t.Fatal(rows)
	}
	enrichICMPInterfaces(rows, nil)
	if rows[0].InterfaceName != "" {
		t.Fatal("retained stale name", rows)
	}
}
