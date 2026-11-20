// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/zyvorai/netra/internal/flowlog"
)

// FlowLogQuerier is the narrow surface of flowlog.Log (and store.Store)
// that FlowLogStore needs.
type FlowLogQuerier interface {
	Query(q flowlog.Query) flowlog.Result
}

// FlowLogStore adapts the controller's bounded flow history into a
// counterfactual.Store. DNS/SNI are copied when the flowlog retained them
// (best-effort join at ingest); empty means unobserved on that delta.
type FlowLogStore struct {
	Log FlowLogQuerier
}

// Query implements Store.
func (s FlowLogStore) Query(_ context.Context, q Query) ([]Flow, error) {
	if s.Log == nil {
		return nil, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = flowlog.DefaultMax
	}
	res := s.Log.Query(flowlog.Query{
		Since: q.Start,
		Until: q.End,
		Limit: limit,
	})
	out := make([]Flow, 0, len(res.Records))
	for _, rec := range res.Records {
		f, ok := RecordToFlow(rec)
		if !ok {
			continue
		}
		if q.Workload != "" && f.Workload.Key() != q.Workload {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out, nil
}

// RecordToFlow maps one flowlog delta into a counterfactual Flow.
// Returns false when the peer address is missing or unparseable.
func RecordToFlow(rec flowlog.Record) (Flow, bool) {
	peer, err := netip.ParseAddr(strings.TrimSpace(rec.Peer))
	if err != nil || !peer.IsValid() {
		return Flow{}, false
	}
	dir := DirectionEgress
	if strings.EqualFold(strings.TrimSpace(rec.Direction), "ingress") {
		dir = DirectionIngress
	}
	proto := ProtocolTCP
	switch strings.ToLower(strings.TrimSpace(rec.Protocol)) {
	case "udp":
		proto = ProtocolUDP
	case "icmp", "icmpv6":
		proto = ProtocolICMP
	case "tcp", "":
		proto = ProtocolTCP
	default:
		proto = ProtocolAny
	}
	kind := strings.TrimSpace(rec.WorkloadKind)
	name := strings.TrimSpace(rec.WorkloadName)
	ns := strings.TrimSpace(rec.Namespace)
	pod := strings.TrimSpace(rec.Pod)
	if kind == "" {
		if pod != "" {
			kind = "pod"
		} else {
			kind = "host"
		}
	}
	if name == "" {
		name = pod
	}
	if name == "" {
		name = strings.TrimSpace(rec.Node)
	}
	if name == "" {
		name = "unknown"
	}
	f := Flow{
		Timestamp: rec.ObservedAt,
		Protocol:  proto,
		Direction: dir,
		Workload: WorkloadRef{
			Kind:      kind,
			Namespace: ns,
			Name:      name,
		},
		Packets: rec.Packets,
		Bytes:   rec.Bytes,
		DNSName: strings.TrimSpace(rec.DNSName),
		TLSSNI:  strings.TrimSpace(rec.TLSSNI),
	}
	if dir == DirectionEgress {
		f.DstIP = peer
		f.DstPort = rec.Port
	} else {
		f.SrcIP = peer
		f.SrcPort = rec.Port
	}
	return f, true
}
