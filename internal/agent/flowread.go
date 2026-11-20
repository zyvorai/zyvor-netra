// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"encoding/binary"
	"net"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// The readers below produce the same report content as the loops they replaced
// (see legacy_readers_test.go, which keeps those loops as the reference), but do
// the work in a different order. Those loops walked every entry of a table of up
// to 131 072 with two syscalls each, formatted two IP strings per entry, sorted
// all of them, and then kept the first 1 000. These rank on the raw counters in
// one batched pass, keep only the best N, and decode, format and enrich just
// those N. Ties are broken by key, so a read of an unchanged table is stable.

const (
	// workload_flow_stats key: cgroup[0:8] src_port[12:14] dst_port[14:16]
	// family[8] proto[11] dir[9] hook[10] src[16:32] dst[32:48]; value 32 bytes.
	workloadFlowKeySize, flowValSize = 48, 32
	// flow_stats key is 40 bytes with the same value.
	globalFlowKeySize = 40
	tcpHealthKeySize  = 56
	tcpHealthValSize  = 136
	udpHealthKeySize  = 56
	udpHealthValSize  = 24
	quicKeySize       = 32
	quicValSize       = 24
)

func packets(_, v []byte) (uint64, bool) { return native.Uint64(v[0:8]), true }

func (a *Agent) readStats() ([]models.DestinationStat, error) {
	rows, err := a.topRows("workload_flow_stats", models.ReportCapFlows, workloadFlowKeySize, flowValSize, packets)
	if err != nil {
		return nil, err
	}
	out := make([]models.DestinationStat, 0, len(rows))
	for _, r := range rows {
		k, v := r.Key, r.Val
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
	// Preserve interface-level TCX/XDP counters as unattributed rows. Cgroup rows
	// come from workload_flow_stats so we do not double count them.
	if a.collection.Maps["flow_stats"] != nil {
		grows, err := a.topRows("flow_stats", models.ReportCapFlows, globalFlowKeySize, flowValSize, func(k, v []byte) (uint64, bool) {
			if k[2] == 2 {
				return 0, false
			}
			return native.Uint64(v[0:8]), true
		})
		if err != nil {
			return nil, err
		}
		for _, r := range grows {
			gk, gv := r.Key, r.Val
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
	}
	// The best N of the union is within the best N of each part.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	if len(out) > models.ReportCapFlows {
		out = out[:models.ReportCapFlows]
	}
	return out, nil
}

// tcpHealthScore ranks a flow by how unhealthy it looks: retransmits, RTOs and
// smoothed RTT, with the weights the report has always used.
func tcpHealthScore(_, v []byte) (uint64, bool) {
	return native.Uint64(v[24:32])*1000 + native.Uint64(v[32:40])*10000 + native.Uint64(v[48:56])/1000, true
}

func (a *Agent) readTCPHealth() ([]models.TCPHealthStat, error) {
	rows, err := a.topRows("tcp_health", 1000, tcpHealthKeySize, tcpHealthValSize, tcpHealthScore)
	if err != nil {
		return nil, err
	}
	out := make([]models.TCPHealthStat, 0, len(rows))
	for _, r := range rows {
		k, v := r.Key, r.Val
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
	return out, nil
}

func (a *Agent) readUDPFlowHealth() ([]models.UDPFlowHealthStat, error) {
	rows, err := a.topRows("udp_flow_health", 1000, udpHealthKeySize, udpHealthValSize, func(_, v []byte) (uint64, bool) {
		return native.Uint64(v[8:16]), true // bytes
	})
	if err != nil {
		return nil, err
	}
	out := make([]models.UDPFlowHealthStat, 0, len(rows))
	for _, r := range rows {
		var k [56]byte
		var v [24]byte
		copy(k[:], r.Key)
		copy(v[:], r.Val)
		st := decodeUDPFlowHealth(k, v)
		a.enrichUDPFlowHealth(&st)
		out = append(out, st)
	}
	return out, nil
}

func (a *Agent) readQUICObserved() ([]models.QUICObservedStat, error) {
	rows, err := a.topRows("quic_observed", 1000, quicKeySize, quicValSize, func(_, v []byte) (uint64, bool) {
		return native.Uint64(v[8:16]), true // long-header packets
	})
	if err != nil {
		return nil, err
	}
	out := make([]models.QUICObservedStat, 0, len(rows))
	for _, r := range rows {
		var k [32]byte
		var v [24]byte
		copy(k[:], r.Key)
		copy(v[:], r.Val)
		st := decodeQUICObserved(k, v)
		a.enrichQUICObserved(&st)
		out = append(out, st)
	}
	return out, nil
}
