// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package denysim

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Caveat is fixed on every response. This preview is observed-counter
// matching, never a policy determination and never an apply.
const Caveat = "Observed-counter preview only — not a policy determination and not an apply. Hits are cumulative counters from the latest non-stale agent reports (and sampled socket events for process matches). Absence of a hit means Netra did not observe matching traffic in this window, not that the destination is unused or that enforce would be a no-op. Process matching is best-effort on sampled FastPath events; comm is not a cryptographic identity."

const (
	KindIP      = "ip"
	KindCIDR    = "cidr"
	KindPort    = "port"
	KindDNS     = "dns"
	KindSNI     = "sni"
	KindProcess = "process"
)

// Proposal is one emergency deny the operator is considering.
type Proposal struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Direction string `json:"direction,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      uint16 `json:"port,omitempty"`

	Namespace    string `json:"namespace,omitempty"`
	Pod          string `json:"pod,omitempty"`
	WorkloadKind string `json:"workloadKind,omitempty"`
	WorkloadName string `json:"workloadName,omitempty"`

	Limit int `json:"limit,omitempty"`
}

// Hit is one observed counter group that the proposal would have matched.
type Hit struct {
	Source         string `json:"source"`
	Node           string `json:"node"`
	Namespace      string `json:"namespace,omitempty"`
	Pod            string `json:"pod,omitempty"`
	WorkloadKind   string `json:"workloadKind,omitempty"`
	WorkloadName   string `json:"workloadName,omitempty"`
	Destination    string `json:"destination"`
	Direction      string `json:"direction,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Evidence       string `json:"evidence"`
	Packets        uint64 `json:"packets"`
	Bytes          uint64 `json:"bytes"`
	AlreadyBlocked uint64 `json:"alreadyBlocked,omitempty"`
}

// Result is the review-only preview.
type Result struct {
	Proposal     Proposal `json:"proposal"`
	AgentsSeen   int      `json:"agentsSeen"`
	AgentsStale  int      `json:"agentsStale"`
	Hits         []Hit    `json:"hits"`
	HitCount     int      `json:"hitCount"`
	Truncated    bool     `json:"truncated"`
	TotalPackets uint64   `json:"totalPackets"`
	TotalBytes   uint64   `json:"totalBytes"`
	Workloads    int      `json:"workloads"`
	Caveat       string   `json:"caveat"`
}

func (p Proposal) normalize() (Proposal, error) {
	p.Kind = strings.ToLower(strings.TrimSpace(p.Kind))
	p.Value = strings.TrimSpace(p.Value)
	p.Direction = strings.ToLower(strings.TrimSpace(p.Direction))
	p.Protocol = strings.ToUpper(strings.TrimSpace(p.Protocol))
	p.Namespace = strings.TrimSpace(p.Namespace)
	p.Pod = strings.TrimSpace(p.Pod)
	p.WorkloadKind = strings.TrimSpace(p.WorkloadKind)
	p.WorkloadName = strings.TrimSpace(p.WorkloadName)
	if p.Direction == "" {
		p.Direction = "both"
	}
	switch p.Direction {
	case "egress", "ingress", "both":
	default:
		return p, fmt.Errorf("direction must be egress, ingress, or both")
	}
	switch p.Kind {
	case KindIP, KindCIDR, KindPort, KindDNS, KindSNI, KindProcess:
	default:
		return p, fmt.Errorf("kind must be ip, cidr, port, dns, sni, or process")
	}
	if p.Value == "" {
		return p, fmt.Errorf("value is required")
	}
	if p.Kind == KindPort && p.Port == 0 {
		n, err := strconv.ParseUint(p.Value, 10, 16)
		if err != nil || n == 0 {
			return p, fmt.Errorf("port value must be a positive integer")
		}
		p.Port = uint16(n)
	}
	if p.Kind == KindIP {
		if _, err := netip.ParseAddr(p.Value); err != nil {
			return p, fmt.Errorf("value is not an IP address")
		}
	}
	if p.Kind == KindCIDR {
		if _, err := netip.ParsePrefix(p.Value); err != nil {
			return p, fmt.Errorf("value is not a CIDR prefix")
		}
	}
	if p.Kind == KindDNS || p.Kind == KindSNI || p.Kind == KindProcess {
		p.Value = strings.ToLower(p.Value)
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 200 {
		p.Limit = 200
	}
	return p, nil
}

func scopeMatch(p Proposal, ns, pod, kind, name string) bool {
	if p.Namespace != "" && !strings.EqualFold(p.Namespace, ns) {
		return false
	}
	if p.Pod != "" && !strings.EqualFold(p.Pod, pod) {
		return false
	}
	if p.WorkloadKind != "" && !strings.EqualFold(p.WorkloadKind, kind) {
		return false
	}
	if p.WorkloadName != "" && !strings.EqualFold(p.WorkloadName, name) {
		return false
	}
	return true
}

func directionMatch(want, have string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	have = strings.ToLower(strings.TrimSpace(have))
	if want == "" || want == "both" || have == "" || have == "both" {
		return true
	}
	return want == have
}

func protocolMatch(want, have string) bool {
	want = strings.ToUpper(strings.TrimSpace(want))
	have = strings.ToUpper(strings.TrimSpace(have))
	if want == "" || want == "ANY" || have == "" || have == "ANY" {
		return true
	}
	return want == have
}

func ipInCIDR(cidr, ip string) bool {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return pfx.Contains(addr)
}

func workloadKey(ns, pod, kind, name string, cgroup uint64) string {
	if ns != "" && (name != "" || pod != "") {
		label := name
		if label == "" {
			label = pod
		}
		if kind == "" {
			kind = "pod"
		}
		return ns + "/" + kind + "/" + label
	}
	if pod != "" {
		return pod
	}
	if cgroup != 0 {
		return fmt.Sprintf("cgroup:%d", cgroup)
	}
	return "unattributed"
}

func hitKey(h Hit) string {
	return strings.Join([]string{h.Source, h.Node, h.Destination, h.Direction, h.Protocol, h.Evidence}, "|")
}

// Preview matches a proposed deny against live agent counters.
func Preview(agents []models.AgentStatus, raw Proposal) (*Result, error) {
	p, err := raw.normalize()
	if err != nil {
		return nil, err
	}
	grouped := map[string]*Hit{}
	agentsSeen, agentsStale := 0, 0

	for _, a := range agents {
		if a.Stale {
			agentsStale++
			continue
		}
		agentsSeen++
		switch p.Kind {
		case KindIP, KindCIDR, KindPort:
			for _, s := range a.Stats {
				if !scopeMatch(p, s.Namespace, s.Pod, s.WorkloadKind, s.WorkloadName) {
					continue
				}
				if !directionMatch(p.Direction, s.Direction) {
					continue
				}
				if !protocolMatch(p.Protocol, s.Protocol) {
					continue
				}
				if !matchTuple(p, s) {
					continue
				}
				dest := s.DestinationIP
				if s.Port != 0 {
					dest = fmt.Sprintf("%s:%d", s.DestinationIP, s.Port)
				}
				addHit(grouped, Hit{
					Source:         workloadKey(s.Namespace, s.Pod, s.WorkloadKind, s.WorkloadName, s.CgroupID),
					Node:           a.Node,
					Namespace:      s.Namespace,
					Pod:            s.Pod,
					WorkloadKind:   s.WorkloadKind,
					WorkloadName:   s.WorkloadName,
					Destination:    dest,
					Direction:      s.Direction,
					Protocol:       s.Protocol,
					Evidence:       "flow-counter",
					Packets:        s.Packets,
					Bytes:          s.Bytes,
					AlreadyBlocked: s.Blocked,
				})
			}
			for _, c := range a.ConnectionAttempts {
				if !scopeMatch(p, c.Namespace, c.Pod, c.WorkloadKind, c.WorkloadName) {
					continue
				}
				if p.Direction == "ingress" {
					continue
				}
				if !protocolMatch(p.Protocol, c.Protocol) {
					continue
				}
				fake := models.DestinationStat{
					DestinationIP: c.RemoteIP,
					Port:          c.RemotePort,
					Protocol:      c.Protocol,
					Direction:     "egress",
				}
				if !matchTuple(p, fake) {
					continue
				}
				dest := c.RemoteIP
				if c.RemotePort != 0 {
					dest = fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort)
				}
				addHit(grouped, Hit{
					Source:         workloadKey(c.Namespace, c.Pod, c.WorkloadKind, c.WorkloadName, c.CgroupID),
					Node:           a.Node,
					Namespace:      c.Namespace,
					Pod:            c.Pod,
					WorkloadKind:   c.WorkloadKind,
					WorkloadName:   c.WorkloadName,
					Destination:    dest,
					Direction:      "egress",
					Protocol:       c.Protocol,
					Evidence:       "connect-attempt",
					Packets:        c.Attempts,
					AlreadyBlocked: c.Blocked,
				})
			}
		case KindDNS:
			for _, d := range a.DNSHealth {
				if !scopeMatch(p, d.Namespace, d.Pod, d.WorkloadKind, d.WorkloadName) {
					continue
				}
				if strings.ToLower(strings.TrimSpace(d.Name)) != p.Value {
					continue
				}
				addHit(grouped, Hit{
					Source:       workloadKey(d.Namespace, d.Pod, d.WorkloadKind, d.WorkloadName, d.CgroupID),
					Node:         a.Node,
					Namespace:    d.Namespace,
					Pod:          d.Pod,
					WorkloadKind: d.WorkloadKind,
					WorkloadName: d.WorkloadName,
					Destination:  d.Name,
					Direction:    "egress",
					Protocol:     "UDP",
					Evidence:     "dns-health",
					Packets:      d.Queries,
				})
			}
		case KindSNI:
			for _, t := range a.TLSMetadata {
				if !scopeMatch(p, t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName) {
					continue
				}
				if strings.ToLower(strings.TrimSpace(t.SNI)) != p.Value {
					continue
				}
				addHit(grouped, Hit{
					Source:         workloadKey(t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName, t.CgroupID),
					Node:           a.Node,
					Namespace:      t.Namespace,
					Pod:            t.Pod,
					WorkloadKind:   t.WorkloadKind,
					WorkloadName:   t.WorkloadName,
					Destination:    t.SNI,
					Direction:      "egress",
					Protocol:       "TCP",
					Evidence:       "tls-sni",
					Packets:        t.Handshakes,
					AlreadyBlocked: t.Blocked,
				})
			}
		case KindProcess:
			for _, ev := range a.Events {
				if !scopeMatch(p, "", "", "", "") {
					continue
				}
				if !directionMatch(p.Direction, ev.Direction) {
					continue
				}
				if strings.ToLower(strings.TrimSpace(ev.Comm)) != p.Value {
					continue
				}
				dest := ev.DestinationIP
				if ev.DestinationPort != 0 {
					dest = fmt.Sprintf("%s:%d", ev.DestinationIP, ev.DestinationPort)
				}
				addHit(grouped, Hit{
					Source:      ev.Comm,
					Node:        a.Node,
					Destination: dest,
					Direction:   ev.Direction,
					Protocol:    ev.Protocol,
					Evidence:    "sampled-event",
					Packets:     1,
					Bytes:       uint64(ev.Length),
				})
			}
		}
	}

	hits := make([]Hit, 0, len(grouped))
	workloads := map[string]struct{}{}
	var packets, bytes uint64
	for _, h := range grouped {
		hits = append(hits, *h)
		workloads[h.Source] = struct{}{}
		packets += h.Packets
		bytes += h.Bytes
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Packets != hits[j].Packets {
			return hits[i].Packets > hits[j].Packets
		}
		if hits[i].Source != hits[j].Source {
			return hits[i].Source < hits[j].Source
		}
		return hits[i].Destination < hits[j].Destination
	})
	truncated := false
	if len(hits) > p.Limit {
		hits = hits[:p.Limit]
		truncated = true
	}
	return &Result{
		Proposal:     p,
		AgentsSeen:   agentsSeen,
		AgentsStale:  agentsStale,
		Hits:         hits,
		HitCount:     len(hits),
		Truncated:    truncated,
		TotalPackets: packets,
		TotalBytes:   bytes,
		Workloads:    len(workloads),
		Caveat:       Caveat,
	}, nil
}

func matchTuple(p Proposal, s models.DestinationStat) bool {
	switch p.Kind {
	case KindIP:
		addr := s.DestinationIP
		if strings.EqualFold(p.Direction, "ingress") {
			addr = s.SourceIP
			if addr == "" {
				addr = s.DestinationIP
			}
		}
		if strings.EqualFold(p.Direction, "both") {
			return strings.EqualFold(s.DestinationIP, p.Value) || strings.EqualFold(s.SourceIP, p.Value)
		}
		return strings.EqualFold(addr, p.Value)
	case KindCIDR:
		if strings.EqualFold(p.Direction, "ingress") {
			if s.SourceIP != "" && ipInCIDR(p.Value, s.SourceIP) {
				return true
			}
			return ipInCIDR(p.Value, s.DestinationIP)
		}
		if strings.EqualFold(p.Direction, "both") {
			return ipInCIDR(p.Value, s.DestinationIP) || (s.SourceIP != "" && ipInCIDR(p.Value, s.SourceIP))
		}
		return ipInCIDR(p.Value, s.DestinationIP)
	case KindPort:
		if s.Port != p.Port {
			return false
		}
		return protocolMatch(p.Protocol, s.Protocol)
	}
	return false
}

func addHit(grouped map[string]*Hit, h Hit) {
	k := hitKey(h)
	if cur, ok := grouped[k]; ok {
		cur.Packets += h.Packets
		cur.Bytes += h.Bytes
		cur.AlreadyBlocked += h.AlreadyBlocked
		return
	}
	cp := h
	grouped[k] = &cp
}
