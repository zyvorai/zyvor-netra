// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package flowexport

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

var base = time.Unix(1_700_000_000, 0)

func rec(sec int, peer string, port uint16, proto, dir string, bytes, pkts uint64) flowlog.Record {
	return flowlog.Record{ObservedAt: base.Add(time.Duration(sec) * time.Second), Node: "n1", Namespace: "shop", WorkloadName: "cart", Peer: peer, Port: port, Protocol: proto, Direction: dir, Bytes: bytes, Packets: pkts}
}

func TestBuildAggregatesAndMapsFields(t *testing.T) {
	s := Build([]flowlog.Record{
		rec(0, "203.0.113.9", 443, "TCP", "egress", 100, 2),
		rec(5, "203.0.113.9", 443, "tcp", "EGRESS", 50, 1),
		rec(-3, "203.0.113.9", 443, "TCP", "egress", 10, 1),
		rec(1, "2001:db8::1", 53, "UDP", "ingress", 400, 4),
		rec(2, "::ffff:198.51.100.2", 80, "TCP", "ingress", 1, 1),
		rec(3, "weird peer", 0, "GRE", "", 1, 1),
	}, 0)
	if s.Observed != 6 || s.Aggregated != 4 || s.Truncated || len(s.Flows) != 4 || len(s.Limitations) == 0 {
		t.Fatalf("%+v", s)
	}
	top := s.Flows[0] // 400 bytes ingress v6
	if top.SourceIPv6Address != "2001:db8::1" || top.DestinationIPv6Address != "" || *top.FlowDirection != 0 || *top.ProtocolIdentifier != 17 || top.DestinationTransportPort != 53 {
		t.Fatalf("top %+v", top)
	}
	agg := s.Flows[1]
	if agg.DestinationIPv4Address != "203.0.113.9" || agg.OctetDeltaCount != 160 || agg.PacketDeltaCount != 4 || agg.NetraObservations != 3 || *agg.FlowDirection != 1 || *agg.ProtocolIdentifier != 6 {
		t.Fatalf("agg %+v", agg)
	}
	if agg.FlowStartMilliseconds != base.Add(-3*time.Second).UnixMilli() || agg.FlowEndMilliseconds != base.Add(5*time.Second).UnixMilli() {
		t.Fatalf("window %d..%d", agg.FlowStartMilliseconds, agg.FlowEndMilliseconds)
	}
	var mapped, odd Flow
	for _, f := range s.Flows {
		if f.SourceIPv4Address == "198.51.100.2" {
			mapped = f
		}
		if f.NetraPeer == "weird peer" {
			odd = f
		}
	}
	if mapped.SourceIPv4Address == "" {
		t.Fatal("v4-mapped v6 address should unmap to IPv4")
	}
	if odd.NetraPeer == "" || odd.ProtocolIdentifier != nil || odd.FlowDirection != nil {
		t.Fatalf("unknown proto, direction and non-IP peer stay unmapped: %+v", odd)
	}
}

func TestLimitsAndCardinality(t *testing.T) {
	var recs []flowlog.Record
	for i := 0; i < 5000; i++ {
		recs = append(recs, rec(i, fmt.Sprintf("10.%d.%d.1", i/250, i%250), 80, "TCP", "egress", uint64(i), 1))
	}
	s := Build(recs, 100)
	if len(s.Flows) != 100 || !s.Truncated || s.Aggregated != 5000 {
		t.Fatalf("flows=%d truncated=%v aggregated=%d", len(s.Flows), s.Truncated, s.Aggregated)
	}
	if s.Flows[0].OctetDeltaCount != 4999 {
		t.Fatalf("largest first, got %d", s.Flows[0].OctetDeltaCount)
	}
	if got := len(Build(recs, 1_000_000).Flows); got != 5000 {
		t.Fatalf("limit above max is clamped, not rejected: %d", got)
	}
	if got := len(Build(recs, -4).Flows); got != DefaultFlows {
		t.Fatalf("negative limit selects the default: %d", got)
	}
	if empty := Build(nil, 10); empty.Flows == nil || len(empty.Flows) != 0 {
		t.Fatal("empty export must serialise as []")
	}
}

func TestCSVInjectionAndQuoting(t *testing.T) {
	r := rec(0, "=cmd|' /C calc'!A0", 1, "TCP", "egress", 1, 1)
	r.Namespace = "+SUM(1)"
	r.WorkloadName = "-2+3"
	r.Node = "@x"
	r.AppProtocol = "a,\"b\"\nc"
	s := Build([]flowlog.Record{r}, 10)
	var buf bytes.Buffer
	if err := WriteCSV(&buf, s.Flows); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output must be valid CSV: %v", err)
	}
	if len(rows) != 2 || len(rows[0]) != len(CSVHeader) || len(rows[1]) != len(CSVHeader) {
		t.Fatalf("shape %v", rows)
	}
	for i, h := range CSVHeader {
		v := rows[1][i]
		if strings.HasPrefix(v, "=") || strings.HasPrefix(v, "+") || strings.HasPrefix(v, "-") || strings.HasPrefix(v, "@") {
			t.Fatalf("column %s starts with a formula character: %q", h, v)
		}
	}
	if rows[1][11] != "'@x" || rows[1][12] != "'+SUM(1)" || rows[1][13] != "'-2+3" || rows[1][15] != "'=cmd|' /C calc'!A0" {
		t.Fatalf("cells %q", rows[1])
	}
}

func TestJSONLinesAndNames(t *testing.T) {
	s := Build([]flowlog.Record{rec(0, "192.0.2.1", 22, "TCP", "ingress", 7, 1), rec(0, "192.0.2.2", 22, "TCP", "ingress", 9, 1)}, 10)
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, s.Flows); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines %v", lines)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"flowStartMilliseconds", "flowEndMilliseconds", "sourceIPv4Address", "destinationTransportPort", "protocolIdentifier", "octetDeltaCount", "packetDeltaCount", "flowDirection"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing IPFIX element %s in %v", k, m)
		}
	}
	if m["flowDirection"].(float64) != 0 {
		t.Fatalf("ingress is flowDirection 0, got %v", m["flowDirection"])
	}
}
