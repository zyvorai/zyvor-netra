// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"github.com/zyvorai/netra/internal/models"
	"net"
	"sort"
)

func decodeICMPError(k [8]byte, v [24]byte) models.ICMPErrorStat {
	return models.ICMPErrorStat{
		InterfaceIndex: native.Uint32(k[0:4]), Family: familyName(k[4]),
		Type: k[5], Code: k[6], Direction: dirName(k[7]), Hook: "tc",
		Packets: native.Uint64(v[0:8]), AdvertisedMTU: native.Uint32(v[8:12]),
		LastSeenNS: native.Uint64(v[16:24]),
	}
}

func (a *Agent) readICMPErrors() ([]models.ICMPErrorStat, error) {
	m := a.collection.Maps["icmp_errors"]
	// Allows old BPF objects to report their existing evidence during upgrades.
	if m == nil {
		return nil, nil
	}
	it := m.Iterate()
	var k [8]byte
	var v [24]byte
	out := make([]models.ICMPErrorStat, 0)
	// LRU iteration can revisit keys during concurrent eviction; bound work too.
	seen := make(map[[8]byte]bool)
	for n := 0; n < 4096 && it.Next(&k, &v); n++ {
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, decodeICMPError(k, v))
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	if interfaces, err := net.Interfaces(); err == nil {
		enrichICMPInterfaces(out, interfaces)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Packets != b.Packets {
			return a.Packets > b.Packets
		}
		if a.InterfaceIndex != b.InterfaceIndex {
			return a.InterfaceIndex < b.InterfaceIndex
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Direction < b.Direction
	})
	return out, nil
}

// Names are a current best-effort lookup; keep the recorded index even when
// the interface has disappeared or has been renamed since the observation.
func enrichICMPInterfaces(rows []models.ICMPErrorStat, interfaces []net.Interface) {
	names := make(map[uint32]string, len(interfaces))
	for _, iface := range interfaces {
		if iface.Index > 0 {
			names[uint32(iface.Index)] = iface.Name
		}
	}
	for i := range rows {
		rows[i].InterfaceName = names[rows[i].InterfaceIndex]
	}
}
