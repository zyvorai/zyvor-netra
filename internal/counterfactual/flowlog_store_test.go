// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"context"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

type memFlowLog struct {
	recs []flowlog.Record
}

func (m *memFlowLog) Query(q flowlog.Query) flowlog.Result {
	res := flowlog.Result{Records: []flowlog.Record{}, Limitations: flowlog.Limitations()}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	for i := len(m.recs) - 1; i >= 0; i-- {
		rec := m.recs[i]
		if !q.Since.IsZero() && rec.ObservedAt.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && rec.ObservedAt.After(q.Until) {
			continue
		}
		res.Matched++
		if len(res.Records) < limit {
			res.Records = append(res.Records, rec)
		} else {
			res.Truncated = true
		}
	}
	return res
}

func TestRecordToFlowEgress(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	f, ok := RecordToFlow(flowlog.Record{
		ObservedAt:   now,
		Namespace:    "prod",
		Pod:          "api-1",
		WorkloadKind: "Deployment",
		WorkloadName: "api",
		Peer:         "203.0.113.50",
		Port:         443,
		Protocol:     "TCP",
		Direction:    "egress",
		Packets:      10,
		Bytes:        1000,
	})
	if !ok {
		t.Fatal("expected ok")
	}
	if f.Direction != DirectionEgress || f.DstPort != 443 || !f.DstIP.IsValid() {
		t.Fatalf("bad flow: %+v", f)
	}
	if f.RemoteIP().String() != "203.0.113.50" || f.RemotePort() != 443 {
		t.Fatalf("remote: %s %d", f.RemoteIP(), f.RemotePort())
	}
	if f.Workload.Key() != "Deployment/prod/api" {
		t.Fatalf("workload key %q", f.Workload.Key())
	}
}

func TestFlowLogStoreEvaluateCIDR(t *testing.T) {
	now := time.Now().UTC()
	log := &memFlowLog{recs: []flowlog.Record{
		{
			ObservedAt: now.Add(-30 * time.Minute),
			Namespace:  "prod", Pod: "api-1", WorkloadKind: "pod", WorkloadName: "api-1",
			Peer: "203.0.113.50", Port: 443, Protocol: "TCP", Direction: "egress",
			Packets: 5, Bytes: 500,
		},
		{
			ObservedAt: now.Add(-10 * time.Minute),
			Namespace:  "prod", Pod: "api-1", WorkloadKind: "pod", WorkloadName: "api-1",
			Peer: "198.51.100.9", Port: 80, Protocol: "TCP", Direction: "egress",
			Packets: 2, Bytes: 200,
		},
	}}
	store := FlowLogStore{Log: log}
	pol, err := PolicyFromEmergencyDeny("cidr", "203.0.113.0/24", "egress", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewEvaluator(store).Evaluate(context.Background(), pol, Query{
		Start: now.Add(-time.Hour),
		End:   now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.FlowsSeen != 2 {
		t.Fatalf("flowsSeen=%d", res.FlowsSeen)
	}
	if len(res.Denials) != 1 || res.Denials[0].FlowCount != 1 {
		t.Fatalf("denials=%+v", res.Denials)
	}
	if res.Denials[0].TotalPackets != 5 {
		t.Fatalf("packets=%d", res.Denials[0].TotalPackets)
	}
}

func TestPolicyFromEmergencyDenyProcessRejected(t *testing.T) {
	_, err := PolicyFromEmergencyDeny("process", "curl", "both", "", 0)
	if err == nil {
		t.Fatal("expected error")
	}
}
