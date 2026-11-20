// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// maxAggOps bounds the operations listed per protocol after merging nodes, which
// also bounds the label cardinality of the metrics built from them.
const maxAggOps = 50

// l7SampleView is the cluster-wide picture of sampled application-protocol use:
// which commands, verbs, APIs and gRPC methods workloads issue, and how often they
// fail. Every count is from a rate-limited sample; Estimated scales it back using
// each node's own Eligible/Emitted ratio.
type l7SampleView struct {
	Nodes        []l7SampleNode `json:"nodes"`
	Reporting    int            `json:"nodesReporting"`
	NotReporting int            `json:"nodesNotReporting"`
	// Eligible/Emitted are summed over reporting nodes; ScaleFactor is their ratio.
	Eligible    uint64                `json:"eligible"`
	Emitted     uint64                `json:"emitted"`
	ScaleFactor float64               `json:"scaleFactor,omitempty"`
	Protocols   []l7SampleProtoAgg    `json:"protocols,omitempty"`
	Hosts       []models.L7SampleHost `json:"hosts,omitempty"`
}

type l7SampleNode struct {
	Node        string `json:"node"`
	Reporting   bool   `json:"reporting"`
	Unavailable string `json:"unavailable,omitempty"`
	// Ports are the configured service ports (packet-level sampling); Libraries the
	// instrumented libssl files (TLS plaintext sampling).
	Ports     []string `json:"ports,omitempty"`
	Libraries []string `json:"libraries,omitempty"`
}

type l7SampleProtoAgg struct {
	Protocol string `json:"protocol"`
	// Role is "served" or "issued". A request is seen leaving its client and
	// arriving at its server, so the roles are aggregated separately and must not
	// be added together.
	Role        string                `json:"role"`
	Requests    uint64                `json:"requests"`
	Responses   uint64                `json:"responses"`
	Errors      uint64                `json:"errors"`
	Undecodable uint64                `json:"undecodable,omitempty"`
	GRPC        uint64                `json:"grpc,omitempty"`
	EstRequests float64               `json:"estimatedRequests"`
	Ops         []l7SampleOpAgg       `json:"ops,omitempty"`
	Codes       []models.L7SampleCode `json:"codes,omitempty"`
}

type l7SampleOpAgg struct {
	Op        string  `json:"op"`
	Count     uint64  `json:"count"`
	Estimated float64 `json:"estimated"`
}

// aggregateL7Sample merges the fresh agents' summaries. protocol, when non-empty,
// restricts Protocols to that protocol.
func aggregateL7Sample(agents []models.AgentStatus, protocol string) l7SampleView {
	v := l7SampleView{Nodes: []l7SampleNode{}}
	type key struct{ protocol, role string }
	protos := map[key]*l7SampleProtoAgg{}
	ops := map[key]map[string]*l7SampleOpAgg{}
	codes := map[key]map[[2]string]uint64{}
	hosts := map[[3]string]uint64{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := l7SampleNode{Node: a.Node}
		q := a.L7Sample
		if q == nil || !q.Attached {
			v.NotReporting++
			if q != nil {
				n.Unavailable = q.Unavailable
			}
			v.Nodes = append(v.Nodes, n)
			continue
		}
		n.Reporting, n.Ports = true, q.Ports
		v.Reporting++
		v.Eligible += q.Eligible
		v.Emitted += q.Emitted
		scale := q.ScaleFactor
		if scale < 1 {
			scale = 1 // nothing sampled yet, or counters unreadable: report the raw count
		}
		for _, p := range q.Protocols {
			k := key{p.Protocol, p.Role}
			pa := protos[k]
			if pa == nil {
				pa = &l7SampleProtoAgg{Protocol: p.Protocol, Role: p.Role}
				protos[k] = pa
				ops[k] = map[string]*l7SampleOpAgg{}
				codes[k] = map[[2]string]uint64{}
			}
			pa.Requests += p.Requests
			pa.Responses += p.Responses
			pa.Errors += p.Errors
			pa.Undecodable += p.Undecodable
			pa.GRPC += p.GRPC
			pa.EstRequests += float64(p.Requests) * scale
			for _, o := range p.Ops {
				oa := ops[k][o.Op]
				if oa == nil {
					oa = &l7SampleOpAgg{Op: o.Op}
					ops[k][o.Op] = oa
				}
				oa.Count += o.Count
				oa.Estimated += float64(o.Count) * scale
			}
			for _, c := range p.Codes {
				codes[k][[2]string{c.Code, c.Status}] += c.Count
			}
		}
		for _, h := range q.Hosts {
			hosts[[3]string{h.Role, h.Host, h.Op}] += h.Count
		}
		v.Nodes = append(v.Nodes, n)
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].Node < v.Nodes[j].Node })
	if v.Emitted > 0 {
		v.ScaleFactor = float64(v.Eligible) / float64(v.Emitted)
	}
	for k, pa := range protos {
		if protocol != "" && k.protocol != protocol {
			continue
		}
		var list []l7SampleOpAgg
		for _, oa := range ops[k] {
			list = append(list, *oa)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count != list[j].Count {
				return list[i].Count > list[j].Count
			}
			return list[i].Op < list[j].Op
		})
		if len(list) > maxAggOps {
			rest := l7SampleOpAgg{Op: "OTHER"}
			for _, x := range list[maxAggOps:] {
				rest.Count += x.Count
				rest.Estimated += x.Estimated
			}
			list = append(list[:maxAggOps], rest)
		}
		pa.Ops = list
		for ck, n := range codes[k] {
			pa.Codes = append(pa.Codes, models.L7SampleCode{Code: ck[0], Status: ck[1], Count: n})
		}
		sort.Slice(pa.Codes, func(i, j int) bool {
			if pa.Codes[i].Count != pa.Codes[j].Count {
				return pa.Codes[i].Count > pa.Codes[j].Count
			}
			return pa.Codes[i].Code < pa.Codes[j].Code
		})
		v.Protocols = append(v.Protocols, *pa)
	}
	sort.Slice(v.Protocols, func(i, j int) bool {
		if v.Protocols[i].Protocol != v.Protocols[j].Protocol {
			return v.Protocols[i].Protocol < v.Protocols[j].Protocol
		}
		return v.Protocols[i].Role < v.Protocols[j].Role
	})
	for k, n := range hosts {
		v.Hosts = append(v.Hosts, models.L7SampleHost{Role: k[0], Host: k[1], Op: k[2], Count: n})
	}
	sort.Slice(v.Hosts, func(i, j int) bool {
		if v.Hosts[i].Count != v.Hosts[j].Count {
			return v.Hosts[i].Count > v.Hosts[j].Count
		}
		return v.Hosts[i].Role+v.Hosts[i].Host+v.Hosts[i].Op < v.Hosts[j].Role+v.Hosts[j].Host+v.Hosts[j].Op
	})
	if len(v.Hosts) > 50 {
		v.Hosts = v.Hosts[:50]
	}
	return v
}

// l7Sampled serves GET /api/v1/l7/sampled?node=NAME&protocol=NAME.
func (s *Server) l7Sampled(w http.ResponseWriter, r *http.Request) {
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	if node := r.URL.Query().Get("node"); node != "" {
		kept := agents[:0:0]
		for _, a := range agents {
			if a.Node == node {
				kept = append(kept, a)
			}
		}
		agents = kept
	}
	writeJSON(w, http.StatusOK, aggregateL7Sample(agents, r.URL.Query().Get("protocol")))
}

// writeL7SampleMetrics adds the sampled counts to /metrics. Labels are protocol
// plus an operation from an allowlist or a validated gRPC path (at most maxAggOps
// per protocol), or a bounded status/error code; no hosts, addresses or payload
// text. The values are sampled counts (see netra_l7_sample_scale_factor for the
// factor to estimate real rates), gauges of per-agent running totals.
func writeL7SampleMetrics(w http.ResponseWriter, agents []models.AgentStatus) {
	writeSampleMetrics(w, agents, "netra_l7_sample", "sampled application")
}

// writeSampleMetrics writes one family of sampled-protocol series under prefix.
// what describes the source in the help text.
func writeSampleMetrics(w http.ResponseWriter, agents []models.AgentStatus, prefix, what string) {
	v := aggregateL7Sample(agents, "")
	metricGauge(w, prefix+"_nodes_reporting", "Fresh node agents running sampled L7 protocol observation.", float64(v.Reporting))
	metricGauge(w, prefix+"_nodes_not_reporting", "Fresh node agents not running it (off, an older agent, or it could not start).", float64(v.NotReporting))
	if v.Reporting == 0 {
		return
	}
	if v.ScaleFactor > 0 {
		metricGauge(w, prefix+"_scale_factor", "Eligible segments divided by sampled ones, cluster-wide: multiply the sampled counts by it to estimate real rates.", v.ScaleFactor)
	}
	fmt.Fprintf(w, "# HELP %s_requests %s\n# TYPE %s_requests gauge\n", prefix, "Sampled "+what+" requests by protocol, role and operation (Redis command, SQL verb, Kafka API, gRPC method). role=served: requests arriving at services on the node; role=issued: requests its workloads send. Do not add the two roles together: each request is seen once in each.", prefix)
	for _, p := range v.Protocols {
		for _, o := range p.Ops {
			fmt.Fprintf(w, prefix+"_requests{protocol=\"%s\",role=\"%s\",op=\"%s\"} %d\n", promLabel(p.Protocol), promLabel(p.Role), promLabel(o.Op), o.Count)
		}
	}
	fmt.Fprintf(w, "# HELP %s_responses %s\n# TYPE %s_responses gauge\n", prefix, "Sampled "+what+" responses by protocol and outcome.", prefix)
	for _, p := range v.Protocols {
		fmt.Fprintf(w, prefix+"_responses{protocol=\"%s\",role=\"%s\",status=\"ok\"} %d\n", promLabel(p.Protocol), promLabel(p.Role), p.Responses-min(p.Errors, p.Responses))
		fmt.Fprintf(w, prefix+"_responses{protocol=\"%s\",role=\"%s\",status=\"error\"} %d\n", promLabel(p.Protocol), promLabel(p.Role), p.Errors)
	}
	fmt.Fprintf(w, "# HELP %s_error_codes %s\n# TYPE %s_error_codes gauge\n", prefix, "Sampled error responses by protocol and code (Redis error kind, SQLSTATE class, HTTP or gRPC status).", prefix)
	for _, p := range v.Protocols {
		for _, c := range p.Codes {
			if c.Status == "error" {
				fmt.Fprintf(w, prefix+"_error_codes{protocol=\"%s\",role=\"%s\",code=\"%s\"} %d\n", promLabel(p.Protocol), promLabel(p.Role), promLabel(c.Code), c.Count)
			}
		}
	}
	fmt.Fprintf(w, "# HELP %s_undecodable %s\n# TYPE %s_undecodable gauge\n", prefix, "Sampled HTTP/2 header blocks that could not be decoded without connection state.", prefix)
	for _, p := range v.Protocols {
		if p.Undecodable > 0 {
			fmt.Fprintf(w, prefix+"_undecodable{protocol=\"%s\",role=\"%s\"} %s\n", promLabel(p.Protocol), promLabel(p.Role), strconv.FormatUint(p.Undecodable, 10))
		}
	}
}

// tlsAsL7 presents each agent's TLS plaintext summary in the shape the sampled-
// protocol aggregation understands, so the same merging, scaling and label
// bounds apply. The instrumented libraries ride in Ports.
func tlsAsL7(agents []models.AgentStatus) []models.AgentStatus {
	out := make([]models.AgentStatus, len(agents))
	for i, a := range agents {
		out[i] = a
		out[i].L7Sample = nil
		if q := a.TLSSample; q != nil {
			out[i].L7Sample = &models.L7SampleSummary{
				Attached: q.Attached, Unavailable: q.Unavailable, Ports: q.Libraries,
				Eligible: q.Eligible, Emitted: q.Emitted, RateLimited: q.RateLimited, RingbufFull: q.RingbufFull,
				ScaleFactor: q.ScaleFactor, Seen: q.Seen, Classified: q.Classified, Overflow: q.Overflow,
				Protocols: q.Protocols, Hosts: q.Hosts,
			}
		}
	}
	return out
}

// tlsSampled serves GET /api/v1/l7/tls?node=NAME&protocol=NAME: the same view as
// /api/v1/l7/sampled, for application protocols observed as plaintext at OpenSSL.
func (s *Server) tlsSampled(w http.ResponseWriter, r *http.Request) {
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	if node := r.URL.Query().Get("node"); node != "" {
		kept := agents[:0:0]
		for _, a := range agents {
			if a.Node == node {
				kept = append(kept, a)
			}
		}
		agents = kept
	}
	v := aggregateL7Sample(tlsAsL7(agents), r.URL.Query().Get("protocol"))
	for i := range v.Nodes {
		v.Nodes[i].Libraries, v.Nodes[i].Ports = v.Nodes[i].Ports, nil
	}
	writeJSON(w, http.StatusOK, v)
}

// writeTLSSampleMetrics adds the TLS plaintext family to /metrics. Same bounded
// labels as the packet-level family; only operation names and coarse outcomes.
func writeTLSSampleMetrics(w http.ResponseWriter, agents []models.AgentStatus) {
	writeSampleMetrics(w, tlsAsL7(agents), "netra_tls_sample", "TLS plaintext (observed at OpenSSL)")
}
