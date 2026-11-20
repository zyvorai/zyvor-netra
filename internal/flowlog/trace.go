// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package flowlog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// PodIP names the workload that owns an address.
type PodIP struct {
	Namespace string
	Name      string
}

// Span is one inferred hop. Parent links exist only when the peer IP is
// a known pod and that pod has its own egress within a few seconds.
// There is no propagated trace context.
type Span struct {
	TraceID     string    `json:"traceId"`
	SpanID      string    `json:"spanId"`
	ParentID    string    `json:"parentId,omitempty"`
	Name        string    `json:"name"`
	Node        string    `json:"node,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Pod         string    `json:"pod,omitempty"`
	Peer        string    `json:"peer"`
	Port        uint16    `json:"port"`
	Protocol    string    `json:"protocol,omitempty"`
	AppProtocol string    `json:"appProtocol,omitempty"`
	CalleePod   string    `json:"calleePod,omitempty"`
	Comm        string    `json:"comm,omitempty"`
	PID         uint32    `json:"pid,omitempty"`
	Packets     uint64    `json:"packets,omitempty"`
	Start       time.Time `json:"start"`
	Inferred    bool      `json:"inferred"`
}

// TraceResult is GET /api/v1/insights/traces.
type TraceResult struct {
	Spans       []Span   `json:"spans"`
	Count       int      `json:"count"`
	Limitations []string `json:"limitations"`
}

func traceLimitations(podMap bool) []string {
	out := []string{
		"Inferred from flow edges. No W3C traceparent is read or written.",
		"A child span is the callee pod's next egress within 5 seconds. It can be wrong.",
		"HTTP status is not a span attribute. Cleartext HTTP/1 status counts live on the RED and L7 boards, not on these spans.",
		"This is not the SIEM otlp-trace export, which is still one parentless span per blocked event.",
	}
	if !podMap {
		out = append(out, "Pod IP map was unavailable, so hops are not linked.")
	}
	return out
}

// Traces builds a service path from flow records and a pod IP map.
// podIPs may be nil.
func Traces(recs []Record, podIPs map[string]PodIP) TraceResult {
	const link = 5 * time.Second
	spans := make([]Span, 0, len(recs))
	for _, rec := range recs {
		if rec.Peer == "" {
			continue
		}
		name := rec.Pod
		if name == "" {
			name = rec.Node
		}
		if name == "" {
			name = "unknown"
		}
		sp := Span{
			Name:        fmt.Sprintf("%s → %s:%d", name, rec.Peer, rec.Port),
			Node:        rec.Node,
			Namespace:   rec.Namespace,
			Pod:         rec.Pod,
			Peer:        rec.Peer,
			Port:        rec.Port,
			Protocol:    rec.Protocol,
			AppProtocol: rec.AppProtocol,
			Comm:        rec.Comm,
			PID:         rec.PID,
			Packets:     rec.Packets,
			Start:       rec.ObservedAt,
			Inferred:    true,
		}
		if ref, ok := podIPs[rec.Peer]; ok && ref.Name != "" {
			sp.CalleePod = ref.Namespace + "/" + ref.Name
		}
		sp.SpanID = spanID(sp)
		sp.TraceID = sp.SpanID
		spans = append(spans, sp)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start.Before(spans[j].Start) })
	for i := range spans {
		if spans[i].CalleePod == "" {
			continue
		}
		for j := range spans {
			if i == j || spans[j].ParentID != "" {
				continue
			}
			callee := spans[j].Namespace + "/" + spans[j].Pod
			if spans[j].Pod == "" || callee != spans[i].CalleePod {
				continue
			}
			dt := spans[j].Start.Sub(spans[i].Start)
			if dt < 0 || dt > link {
				continue
			}
			spans[j].ParentID = spans[i].SpanID
			spans[j].TraceID = spans[i].TraceID
			break
		}
	}
	// Children already copied the parent's trace id. Propagate one more
	// hop so a grandchild shares the root id when the parent was linked
	// in this same pass (parent may have been later in the slice).
	idToTrace := map[string]string{}
	for _, sp := range spans {
		idToTrace[sp.SpanID] = sp.TraceID
	}
	for i := range spans {
		if spans[i].ParentID == "" {
			continue
		}
		if root, ok := idToTrace[spans[i].ParentID]; ok && root != "" {
			spans[i].TraceID = root
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start.After(spans[j].Start) })
	if len(spans) > 200 {
		spans = spans[:200]
	}
	return TraceResult{Spans: spans, Count: len(spans), Limitations: traceLimitations(podIPs != nil)}
}

func spanID(sp Span) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%d|%s", sp.Node, sp.Pod, sp.Peer, sp.Protocol, sp.Port, sp.Start.UTC().Format(time.RFC3339Nano))))
	return hex.EncodeToString(sum[:8])
}
