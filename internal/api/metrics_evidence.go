// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/anomaly"
	"github.com/zyvorai/netra/internal/flowlog"
	"github.com/zyvorai/netra/internal/models"
)

// EvidenceLink points at a Netra surface holding evidence for a metric window.
type EvidenceLink struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	Href  string `json:"href"`
	Why   string `json:"why"`
}

// EvidencePeer is one flow-history peer aggregated over the window.
type EvidencePeer struct {
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Peer      string `json:"peer"`
	Port      uint16 `json:"port"`
	Protocol  string `json:"protocol,omitempty"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	Blocked   uint64 `json:"blocked,omitempty"`
	Retrans   uint64 `json:"retransmissions,omitempty"`
	RTOs      uint64 `json:"rtos,omitempty"`
}

// MetricEvidence is GET /api/v1/metrics/evidence.
type MetricEvidence struct {
	Context     string                       `json:"context"`
	Node        string                       `json:"node,omitempty"`
	Namespace   string                       `json:"namespace,omitempty"`
	Workload    string                       `json:"workload,omitempty"`
	After       int64                        `json:"after"`
	Before      int64                        `json:"before"`
	Kinds       []string                     `json:"kinds"`
	Links       []EvidenceLink               `json:"links"`
	FlowRecords int                          `json:"flowRecords"`
	TopPeers    []EvidencePeer               `json:"topPeers"`
	KernelDrops []models.NamedCount          `json:"kernelDrops,omitempty"`
	Captures    []models.CaptureHistoryEntry `json:"captures,omitempty"`
	Anomalous   []anomaly.Ranked             `json:"anomalous,omitempty"`
	Limitations []string                     `json:"limitations"`
}

// evidenceKinds maps a metric context to the evidence that explains it.
func evidenceKinds(ctx string) []string {
	c := strings.ToLower(ctx)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(c, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("drop", "softnet", "shield", "net.errors", "net.fifo", "policy"):
		return []string{"drops", "flows", "capture"}
	case has("tcp", "retrans", "red_errors", "red_duration", "listen", "sockstat"):
		return []string{"tcp", "flows", "capture"}
	case has("dns"):
		return []string{"dns", "flows"}
	case has("red_http", "http", "nginx", "apache", "haproxy", "envoy"):
		return []string{"http", "flows"}
	case has("conntrack"):
		return []string{"conntrack", "flows"}
	default:
		return []string{"flows", "capture"}
	}
}

func (s *Server) metricsEvidence(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		errorJSON(w, http.StatusServiceUnavailable, errAIStoreUnavailable.Error())
		return
	}
	q := r.URL.Query()
	ctx := strings.TrimSpace(q.Get("context"))
	if ctx == "" {
		errorJSON(w, http.StatusBadRequest, "context is required")
		return
	}
	now := time.Now()
	resolve := func(v int64) int64 {
		if v <= 0 {
			return now.Unix() + v
		}
		return v
	}
	after, before := resolve(queryInt(q, "after", -900)), resolve(queryInt(q, "before", 0))
	if after >= before {
		errorJSON(w, http.StatusBadRequest, "after must be before before")
		return
	}
	if before-after > int64(flowlog.DefaultRetain/time.Second) {
		errorJSON(w, http.StatusBadRequest, "window is limited to 7 days (flow history retention)")
		return
	}
	labels := parseLabels(q.Get("labels"))
	ev := MetricEvidence{
		Context: ctx, Node: q.Get("node"), After: after, Before: before,
		Namespace: firstNonEmpty(strings.TrimSpace(q.Get("namespace")), labels["namespace"]),
		Workload:  firstNonEmpty(strings.TrimSpace(q.Get("workload")), labels["workload"]),
		Kinds:     evidenceKinds(ctx),
		TopPeers:  []EvidencePeer{},
		Limitations: []string{
			"Flow peers are flow-history deltas inside the window (7-day retention); unattributed host traffic has no workload.",
			"Kernel drop reasons are the node's current cumulative counters, not window deltas; use ebpf.kernel_drops for the per-second shape.",
			"Captures are listed only when a capture session overlapped the window. No payloads are returned here.",
		},
	}
	pod := labels["pod"]

	from, to := time.Unix(after, 0).UTC(), time.Unix(before, 0).UTC()
	hist := s.store.FlowQuery(flowlog.Query{Since: from, Until: to, Node: ev.Node, Namespace: ev.Namespace, Pod: pod, Limit: flowlog.DefaultMax})
	type pk struct {
		ns, wl, peer, proto string
		port                uint16
	}
	agg := map[pk]*EvidencePeer{}
	for _, rec := range hist.Records {
		if ev.Workload != "" && rec.WorkloadName != ev.Workload && rec.Pod != ev.Workload {
			continue
		}
		ev.FlowRecords++
		k := pk{rec.Namespace, rec.WorkloadName, rec.Peer, rec.Protocol, rec.Port}
		p := agg[k]
		if p == nil {
			p = &EvidencePeer{Namespace: rec.Namespace, Workload: rec.WorkloadName, Peer: rec.Peer, Port: rec.Port, Protocol: rec.Protocol}
			agg[k] = p
		}
		p.Packets += rec.Packets
		p.Bytes += rec.Bytes
		p.Blocked += rec.Blocked
		p.Retrans += rec.Retrans
		p.RTOs += rec.RTOs
	}
	score := func(p *EvidencePeer) uint64 { return p.Bytes }
	switch ev.Kinds[0] {
	case "drops":
		score = func(p *EvidencePeer) uint64 { return p.Blocked }
	case "tcp":
		score = func(p *EvidencePeer) uint64 { return p.Retrans + p.RTOs }
	}
	peers := make([]*EvidencePeer, 0, len(agg))
	for _, p := range agg {
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool {
		a, b := score(peers[i]), score(peers[j])
		if a != b {
			return a > b
		}
		if peers[i].Bytes != peers[j].Bytes {
			return peers[i].Bytes > peers[j].Bytes
		}
		return peers[i].Peer < peers[j].Peer
	})
	for i, p := range peers {
		if i == 10 {
			break
		}
		ev.TopPeers = append(ev.TopPeers, *p)
	}

	if ev.Kinds[0] == "drops" {
		reasons := map[string]uint64{}
		for _, a := range s.store.AgentStatuses(now, s.agentStaleAfter) {
			if ev.Node != "" && a.Node != ev.Node {
				continue
			}
			for _, k := range a.KernelDrops {
				name := k.ReasonName
				if name == "" {
					name = "reason_" + strconv.FormatUint(uint64(k.Reason), 10)
				}
				reasons[name] += k.Count
			}
		}
		for n, c := range reasons {
			ev.KernelDrops = append(ev.KernelDrops, models.NamedCount{Name: n, Count: c})
		}
		sort.Slice(ev.KernelDrops, func(i, j int) bool {
			if ev.KernelDrops[i].Count != ev.KernelDrops[j].Count {
				return ev.KernelDrops[i].Count > ev.KernelDrops[j].Count
			}
			return ev.KernelDrops[i].Name < ev.KernelDrops[j].Name
		})
		if len(ev.KernelDrops) > 10 {
			ev.KernelDrops = ev.KernelDrops[:10]
		}
	}

	for _, c := range s.store.CaptureHistory(500) {
		if ev.Node != "" && c.Node != ev.Node {
			continue
		}
		end := c.EndedAt
		if end.IsZero() {
			end = now
		}
		if c.StartedAt.Before(to.Add(time.Second)) && end.After(from) {
			ev.Captures = append(ev.Captures, c)
		}
	}

	if s.metricsHub != nil {
		var nodes []string
		if ev.Node != "" {
			nodes = []string{ev.Node}
		}
		for _, rk := range anomaly.Summarize(s.metricsHub.Sources(), nodes, after, before, 10, now).Ranked {
			if rk.AnomalyRate > 0 {
				ev.Anomalous = append(ev.Anomalous, rk)
			}
		}
	}
	ev.Links = evidenceLinks(ev, before-after)
	writeJSON(w, http.StatusOK, ev)
}

func evidenceLinks(ev MetricEvidence, window int64) []EvidenceLink {
	nodeQ := url.Values{}
	if ev.Node != "" {
		nodeQ.Set("node", ev.Node)
	}
	with := func(path string, v url.Values) string {
		if len(v) == 0 {
			return path
		}
		return path + "?" + v.Encode()
	}
	fq := url.Values{}
	for k, v := range nodeQ {
		fq[k] = v
	}
	if ev.Namespace != "" {
		fq.Set("namespace", ev.Namespace)
	}
	fq.Set("since", time.Unix(ev.After, 0).UTC().Format(time.RFC3339))
	fq.Set("limit", "500")
	aq := url.Values{"after": {strconv.FormatInt(ev.After, 10)}, "before": {strconv.FormatInt(ev.Before, 10)}}
	if ev.Node != "" {
		aq.Set("nodes", ev.Node)
	}
	var out []EvidenceLink
	for _, k := range ev.Kinds {
		switch k {
		case "drops":
			out = append(out,
				EvidenceLink{"drops", "Drop explanation", with("/api/v1/drops/explain", nodeQ), "kernel skb drop reasons, policy and shield verdicts on this node"},
				EvidenceLink{"drops", "Drop sites", with("/api/v1/ebpf/drop-info", nodeQ), "which kernel function dropped, by reason"})
		case "tcp":
			out = append(out,
				EvidenceLink{"tcp", "TCP events", with("/api/v1/ebpf/tcp-events", nodeQ), "retransmits, RSTs and state transitions from TCP tracepoints"},
				EvidenceLink{"tcp", "Kernel network diagnostics", with("/api/v1/ebpf/kernel-network", nodeQ), "congestion, listen-queue and socket pressure findings"})
		case "dns":
			out = append(out, EvidenceLink{"dns", "DNS findings", with("/api/v1/ebpf/dns-findings", nodeQ), "failing names, NXDOMAIN bursts and resolver latency"})
		case "http":
			out = append(out, EvidenceLink{"http", "Workload RED", "/api/v1/insights/red?window=" + (time.Duration(window) * time.Second).String(), "per-workload rate, errors and SRTT over the same window"})
		case "conntrack":
			out = append(out, EvidenceLink{"conntrack", "Datapath summary", "/api/v1/ebpf/summary", "conntrack occupancy and datapath counters"})
		case "flows":
			out = append(out, EvidenceLink{"flows", "Flow history", with("/api/v1/flows/history", fq), "flow deltas recorded during the window"})
		case "capture":
			out = append(out, EvidenceLink{"capture", "Capture history", "/api/v1/capture/history", "capture sessions and auto-capture artifacts; overlapping ones are listed inline"})
		}
	}
	out = append(out, EvidenceLink{"anomalies", "Anomalies in this window", with("/api/v1/metrics/anomalies", aq), "other metrics that turned anomalous at the same time"})
	return out
}
