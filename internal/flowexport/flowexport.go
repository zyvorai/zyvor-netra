// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package flowexport turns the controller's retained flow deltas
// (internal/flowlog) into flow summary records named after IANA IPFIX
// information elements (sourceIPv4Address, octetDeltaCount, and so on), as
// JSON, JSON lines or CSV. It is an export of what Netra already stores: not
// an IPFIX or NetFlow wire exporter (no template sets, no UDP), and not a
// packet sampler. Records are aggregated per node, workload, peer, port,
// protocol and direction over the requested window, bounded, and never carry
// payloads, command lines or Secret contents.
package flowexport

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/flowlog"
)

const (
	// MaxFlows is the largest number of summary records returned.
	MaxFlows = 10000
	// DefaultFlows is the default.
	DefaultFlows = 1000
	// maxGroups bounds the aggregation map so a hostile record set cannot
	// grow it without limit.
	maxGroups = 200000
)

// Flow is one summary record. JSON names of the first block are IANA IPFIX
// information element names; the netra* fields are Netra extensions.
type Flow struct {
	FlowStartMilliseconds    int64  `json:"flowStartMilliseconds"`
	FlowEndMilliseconds      int64  `json:"flowEndMilliseconds"`
	FlowDirection            *uint8 `json:"flowDirection,omitempty"` // 0 ingress, 1 egress
	SourceIPv4Address        string `json:"sourceIPv4Address,omitempty"`
	DestinationIPv4Address   string `json:"destinationIPv4Address,omitempty"`
	SourceIPv6Address        string `json:"sourceIPv6Address,omitempty"`
	DestinationIPv6Address   string `json:"destinationIPv6Address,omitempty"`
	DestinationTransportPort uint16 `json:"destinationTransportPort,omitempty"`
	ProtocolIdentifier       *uint8 `json:"protocolIdentifier,omitempty"`
	OctetDeltaCount          uint64 `json:"octetDeltaCount"`
	PacketDeltaCount         uint64 `json:"packetDeltaCount"`

	NetraNode         string `json:"netraNode,omitempty"`
	NetraNamespace    string `json:"netraNamespace,omitempty"`
	NetraWorkload     string `json:"netraWorkload,omitempty"`
	NetraAppProtocol  string `json:"netraAppProtocol,omitempty"`
	NetraPeer         string `json:"netraPeer,omitempty"` // only when the peer is not an IP address
	NetraBlockedCount uint64 `json:"netraBlockedPacketCount,omitempty"`
	NetraRetransmits  uint64 `json:"netraRetransmissions,omitempty"`
	NetraObservations int    `json:"netraObservations"`
}

// Summary is the export plus honest bounds.
type Summary struct {
	Flows       []Flow   `json:"flows"`
	Aggregated  int      `json:"aggregated"` // distinct summary records before the limit
	Observed    int      `json:"observedDeltas"`
	Truncated   bool     `json:"truncated"`
	Limitations []string `json:"limitations"`
}

// Limitations are returned with every export.
func Limitations() []string {
	return []string{
		"Summary records are built from retained flow deltas (internal/flowlog), not from packets: counts are Netra's per-report deltas, and the first sample after a controller restart is only a baseline.",
		"The local address of a flow is not recorded, so only the peer address is exported: sourceIPv4/6Address for ingress records, destinationIPv4/6Address for egress. destinationTransportPort is the port Netra recorded for the flow.",
		"flowStartMilliseconds and flowEndMilliseconds are the first and last time a delta was observed in the window, not connection start and end times.",
		"This is a file or HTTP export in IPFIX field names. It is not an IPFIX or NetFlow v9 wire exporter: there are no template sets and nothing is sent over UDP.",
	}
}

func protoNumber(p string) *uint8 {
	var n uint8
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "TCP":
		n = 6
	case "UDP":
		n = 17
	case "ICMP":
		n = 1
	case "ICMPV6", "ICMP6", "IPV6-ICMP":
		n = 58
	case "SCTP":
		n = 132
	default:
		return nil
	}
	return &n
}

func direction(d string) *uint8 {
	var n uint8
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "ingress":
		n = 0
	case "egress":
		n = 1
	default:
		return nil
	}
	return &n
}

type groupKey struct {
	node, ns, wl, peer, proto, dir, app string
	port                                uint16
}

// Build aggregates records into at most limit summary flows, largest by
// bytes first. limit <= 0 selects DefaultFlows; values above MaxFlows are
// clamped.
func Build(records []flowlog.Record, limit int) Summary {
	if limit <= 0 {
		limit = DefaultFlows
	}
	if limit > MaxFlows {
		limit = MaxFlows
	}
	groups := map[groupKey]*Flow{}
	out := Summary{Flows: []Flow{}, Observed: len(records), Limitations: Limitations()}
	for _, r := range records {
		wl := r.WorkloadName
		if wl == "" {
			wl = r.Pod
		}
		k := groupKey{r.Node, r.Namespace, wl, r.Peer, strings.ToUpper(r.Protocol), strings.ToLower(r.Direction), r.AppProtocol, r.Port}
		f := groups[k]
		if f == nil {
			if len(groups) >= maxGroups {
				out.Truncated = true
				continue
			}
			f = &Flow{NetraNode: r.Node, NetraNamespace: r.Namespace, NetraWorkload: wl, NetraAppProtocol: r.AppProtocol,
				DestinationTransportPort: r.Port, ProtocolIdentifier: protoNumber(r.Protocol), FlowDirection: direction(r.Direction)}
			setPeer(f, r.Peer, strings.ToLower(r.Direction))
			f.FlowStartMilliseconds = r.ObservedAt.UnixMilli()
			f.FlowEndMilliseconds = f.FlowStartMilliseconds
			groups[k] = f
		}
		if ms := r.ObservedAt.UnixMilli(); ms < f.FlowStartMilliseconds {
			f.FlowStartMilliseconds = ms
		} else if ms > f.FlowEndMilliseconds {
			f.FlowEndMilliseconds = ms
		}
		f.OctetDeltaCount += r.Bytes
		f.PacketDeltaCount += r.Packets
		f.NetraBlockedCount += r.Blocked
		f.NetraRetransmits += r.Retrans
		f.NetraObservations++
	}
	all := make([]Flow, 0, len(groups))
	for _, f := range groups {
		all = append(all, *f)
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.OctetDeltaCount != b.OctetDeltaCount {
			return a.OctetDeltaCount > b.OctetDeltaCount
		}
		if a.PacketDeltaCount != b.PacketDeltaCount {
			return a.PacketDeltaCount > b.PacketDeltaCount
		}
		return a.NetraNode+a.NetraNamespace+a.NetraWorkload+peerOf(a) < b.NetraNode+b.NetraNamespace+b.NetraWorkload+peerOf(b)
	})
	out.Aggregated = len(all)
	if len(all) > limit {
		all, out.Truncated = all[:limit], true
	}
	out.Flows = all
	return out
}

func peerOf(f Flow) string {
	return f.SourceIPv4Address + f.DestinationIPv4Address + f.SourceIPv6Address + f.DestinationIPv6Address + f.NetraPeer
}

func setPeer(f *Flow, peer, dir string) {
	a, err := netip.ParseAddr(strings.TrimSpace(peer))
	if err != nil {
		f.NetraPeer = peer
		return
	}
	a = a.Unmap()
	ingress := dir == "ingress"
	switch {
	case a.Is4() && ingress:
		f.SourceIPv4Address = a.String()
	case a.Is4():
		f.DestinationIPv4Address = a.String()
	case ingress:
		f.SourceIPv6Address = a.String()
	default:
		f.DestinationIPv6Address = a.String()
	}
}

// WriteJSONL writes one JSON object per line.
func WriteJSONL(w io.Writer, flows []Flow) error {
	enc := json.NewEncoder(w)
	for _, f := range flows {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// CSVHeader is the fixed column order of WriteCSV.
var CSVHeader = []string{
	"flowStartMilliseconds", "flowEndMilliseconds", "flowDirection", "sourceIPv4Address", "destinationIPv4Address",
	"sourceIPv6Address", "destinationIPv6Address", "destinationTransportPort", "protocolIdentifier",
	"octetDeltaCount", "packetDeltaCount", "netraNode", "netraNamespace", "netraWorkload", "netraAppProtocol",
	"netraPeer", "netraBlockedPacketCount", "netraRetransmissions", "netraObservations",
}

// safeCell neutralises spreadsheet formula injection: a cell that starts with
// =, +, -, @, tab or carriage return is prefixed with a single quote. Values
// come from cluster objects and peers, so they are untrusted.
func safeCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func u8(p *uint8) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(int(*p))
}

// WriteCSV writes a header and one row per flow.
func WriteCSV(w io.Writer, flows []Flow) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, f := range flows {
		port := ""
		if f.DestinationTransportPort != 0 {
			port = strconv.Itoa(int(f.DestinationTransportPort))
		}
		row := []string{
			strconv.FormatInt(f.FlowStartMilliseconds, 10), strconv.FormatInt(f.FlowEndMilliseconds, 10), u8(f.FlowDirection),
			f.SourceIPv4Address, f.DestinationIPv4Address, f.SourceIPv6Address, f.DestinationIPv6Address, port, u8(f.ProtocolIdentifier),
			strconv.FormatUint(f.OctetDeltaCount, 10), strconv.FormatUint(f.PacketDeltaCount, 10),
			safeCell(f.NetraNode), safeCell(f.NetraNamespace), safeCell(f.NetraWorkload), safeCell(f.NetraAppProtocol),
			safeCell(f.NetraPeer), strconv.FormatUint(f.NetraBlockedCount, 10), strconv.FormatUint(f.NetraRetransmits, 10),
			strconv.Itoa(f.NetraObservations),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
