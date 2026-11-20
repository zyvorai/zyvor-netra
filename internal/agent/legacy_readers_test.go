// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

// The agent's original map readers, kept verbatim as the reference the new
// bounded top-N readers (mapread.go) must agree with: they walked every entry
// with Map.Iterate, decoded and formatted all of them, sorted all of them, and
// kept the first N. Only the receiver-method names carry a "legacy" prefix.

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

func (a *Agent) legacyReadStats() ([]models.DestinationStat, error) {
	m := a.collection.Maps["workload_flow_stats"]
	if m == nil {
		return nil, fmt.Errorf("workload_flow_stats unavailable")
	}
	it := m.Iterate()
	var k [48]byte
	var v [32]byte
	out := make([]models.DestinationStat, 0, 256)
	for it.Next(&k, &v) {
		cgroupID := native.Uint64(k[0:8])
		family := k[8]
		src, dst := "", ""
		if family == 4 {
			src = net.IP(k[16:20]).String()
			dst = net.IP(k[32:36]).String()
		} else if family == 6 {
			src = net.IP(k[16:32]).String()
			dst = net.IP(k[32:48]).String()
		}
		st := models.DestinationStat{CgroupID: cgroupID, SourceIP: src, SourcePort: binary.BigEndian.Uint16(k[12:14]), DestinationIP: dst, Port: binary.BigEndian.Uint16(k[14:16]), Protocol: protoName(k[11]), Direction: dirName(k[9]), Hook: hookName(k[10]), Packets: native.Uint64(v[0:8]), Bytes: native.Uint64(v[8:16]), Blocked: native.Uint64(v[16:24]), LastSeenNS: native.Uint64(v[24:32])}
		a.enrichStat(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	// Preserve interface-level TCX/XDP counters as unattributed rows. Cgroup rows
	// come from workload_flow_stats so we do not double count them.
	if global := a.collection.Maps["flow_stats"]; global != nil {
		git := global.Iterate()
		var gk [40]byte
		var gv [32]byte
		for git.Next(&gk, &gv) {
			if gk[2] == 2 {
				continue
			}
			family := gk[0]
			src, dst := "", ""
			if family == 4 {
				src = net.IP(gk[8:12]).String()
				dst = net.IP(gk[24:28]).String()
			} else if family == 6 {
				src = net.IP(gk[8:24]).String()
				dst = net.IP(gk[24:40]).String()
			}
			out = append(out, models.DestinationStat{SourceIP: src, SourcePort: binary.BigEndian.Uint16(gk[4:6]), DestinationIP: dst, Port: binary.BigEndian.Uint16(gk[6:8]), Protocol: protoName(gk[3]), Direction: dirName(gk[1]), Hook: hookName(gk[2]), Packets: native.Uint64(gv[0:8]), Bytes: native.Uint64(gv[8:16]), Blocked: native.Uint64(gv[16:24]), LastSeenNS: native.Uint64(gv[24:32])})
		}
		if err := mapIterErr(git.Err()); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	if len(out) > models.ReportCapFlows {
		out = out[:models.ReportCapFlows]
	}
	return out, nil
}

func (a *Agent) legacyReadTCPHealth() ([]models.TCPHealthStat, error) {
	m := a.collection.Maps["tcp_health"]
	if m == nil {
		return nil, fmt.Errorf("tcp_health unavailable")
	}
	it := m.Iterate()
	var k [56]byte
	var v [136]byte
	out := make([]models.TCPHealthStat, 0, 256)
	for it.Next(&k, &v) {
		family := k[8]
		localIP, remoteIP := "", ""
		if family == 4 {
			localIP = net.IP(k[12:16]).String()
			remoteIP = net.IP(k[16:20]).String()
		}
		if family == 6 {
			localIP = net.IP(k[20:36]).String()
			remoteIP = net.IP(k[36:52]).String()
		}
		st := models.TCPHealthStat{
			CgroupID: native.Uint64(k[0:8]), Family: familyName(family), LocalIP: localIP, RemoteIP: remoteIP,
			LocalPort: native.Uint16(k[52:54]), RemotePort: native.Uint16(k[54:56]),
			ActiveEstablished: native.Uint64(v[0:8]), PassiveEstablished: native.Uint64(v[8:16]), Closes: native.Uint64(v[16:24]),
			Retransmissions: native.Uint64(v[24:32]), RTOs: native.Uint64(v[32:40]), RTTSamples: native.Uint64(v[40:48]),
			SRTTUS: native.Uint64(v[48:56]), MinRTTUS: native.Uint64(v[56:64]), SendCWND: native.Uint64(v[64:72]),
			BytesAcked: native.Uint64(v[72:80]), BytesReceived: native.Uint64(v[80:88]), SegmentsIn: native.Uint64(v[88:96]), SegmentsOut: native.Uint64(v[96:104]),
			LastSeenNS: native.Uint64(v[104:112]), PID: native.Uint32(v[112:116]), UID: native.Uint32(v[116:120]), Comm: cString(v[120:136]),
		}
		a.enrichTCPHealth(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		ai := out[i].Retransmissions*1000 + out[i].RTOs*10000 + out[i].SRTTUS/1000
		aj := out[j].Retransmissions*1000 + out[j].RTOs*10000 + out[j].SRTTUS/1000
		return ai > aj
	})
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) legacyReadUDPFlowHealth() ([]models.UDPFlowHealthStat, error) {
	m := a.collection.Maps["udp_flow_health"]
	if m == nil {
		return nil, fmt.Errorf("udp_flow_health unavailable")
	}
	it := m.Iterate()
	var k [56]byte
	var v [24]byte
	out := make([]models.UDPFlowHealthStat, 0, 256)
	for it.Next(&k, &v) {
		st := decodeUDPFlowHealth(k, v)
		a.enrichUDPFlowHealth(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

func (a *Agent) legacyReadQUICObserved() ([]models.QUICObservedStat, error) {
	m := a.collection.Maps["quic_observed"]
	if m == nil {
		return nil, fmt.Errorf("quic_observed unavailable")
	}
	it := m.Iterate()
	var k [32]byte
	var v [24]byte
	out := make([]models.QUICObservedStat, 0, 256)
	for it.Next(&k, &v) {
		st := decodeQUICObserved(k, v)
		a.enrichQUICObserved(&st)
		out = append(out, st)
	}
	if err := mapIterErr(it.Err()); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LongHeaderPackets > out[j].LongHeaderPackets })
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}
