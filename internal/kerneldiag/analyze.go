// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kerneldiag

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Build correlates cumulative protocol counters with softnet, NIC, qdisc and
// sysctl state. A finding is emitted only when evidence exists; a low-looking
// value alone is not proof that increasing a buffer will help.
func Build(agents []models.AgentStatus) models.KernelNetworkDiagnosticsResponse {
	return build(agents, nil)
}

// BuildWindow evaluates current loss using controller-calculated deltas. The
// raw snapshot remains available for inspection, while findings use only the
// requested interval.
func BuildWindow(agents []models.AgentStatus, windows []models.KernelNetworkWindow) models.KernelNetworkDiagnosticsResponse {
	byNode := make(map[string]models.KernelNetworkWindow, len(windows))
	for _, w := range windows {
		byNode[w.Node] = w
	}
	return build(agents, byNode)
}

func build(agents []models.AgentStatus, windows map[string]models.KernelNetworkWindow) models.KernelNetworkDiagnosticsResponse {
	counterLimit := "Kernel and interface counters are cumulative since node boot; compare two reports before treating them as a rate."
	if windows != nil {
		counterLimit = "Findings use controller-calculated interval deltas; raw boot-lifetime totals remain in each node snapshot for reference."
	}
	out := models.KernelNetworkDiagnosticsResponse{
		Limitations: []string{
			counterLimit,
			"A larger buffer can hide overload and increase latency or memory use; validate with a canary and workload SLOs.",
			"Container network namespaces may expose a subset of host sysctls and counters; deploy the agent with host /proc visibility for node diagnosis.",
			"Netra reports commands as operator-reviewed guidance and never changes kernel tunables automatically.",
		},
	}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		n := models.NodeKernelNetworkDiagnostics{Node: a.Node, Snapshot: a.KernelNetwork}
		if windows != nil {
			w, ok := windows[a.Node]
			if !ok {
				w = models.KernelNetworkWindow{Node: a.Node, Warming: true}
			}
			n.Window = &w
			if w.Warming {
				out.Summary.Warming++
			}
			n.Findings = analyzeNode(windowedAgent(a, w), &w)
		} else {
			n.Findings = analyzeNode(a, nil)
		}
		out.Nodes = append(out.Nodes, n)
		out.Summary.Findings += len(n.Findings)
		for _, f := range n.Findings {
			switch f.Severity {
			case "critical":
				out.Summary.Critical++
			case "warning":
				out.Summary.Warnings++
			}
		}
	}
	out.Summary.Nodes = len(out.Nodes)
	sort.Slice(out.Nodes, func(i, j int) bool {
		return findingScore(out.Nodes[i].Findings) > findingScore(out.Nodes[j].Findings)
	})
	return out
}

func analyzeNode(a models.AgentStatus, window *models.KernelNetworkWindow) []models.KernelNetworkFinding {
	tunables := map[string]string{}
	for _, t := range a.KernelNetwork.Tunables {
		tunables[t.Name] = t.Value
	}
	counters := map[string]uint64{}
	for _, c := range a.KernelNetwork.Counters {
		counters[c.Name] = c.Value
	}
	var out []models.KernelNetworkFinding
	add := func(f models.KernelNetworkFinding) {
		if f.Risk == "" {
			f.Risk = "Changing host-wide kernel settings can affect every workload on the node."
		}
		if f.Tunable != "" {
			f.CurrentValue = tunables[f.Tunable]
			if f.CurrentValue != "" && f.SuggestedValue != "" {
				f.ApplyCommand = fmt.Sprintf("sysctl -w %s=%s", f.Tunable, shellValue(f.SuggestedValue))
				f.RollbackCommand = fmt.Sprintf("sysctl -w %s=%s", f.Tunable, shellValue(f.CurrentValue))
			}
		}
		if window != nil && !window.Warming && window.Seconds > 0 && f.Layer != "conntrack" {
			f.WindowSeconds = window.Seconds
			for i := range f.Evidence {
				f.Evidence[i] = strings.Replace(f.Evidence[i], "=", "_delta=", 1)
			}
		}
		out = append(out, f)
	}
	classify := func(v, fiveMinuteCritical uint64) string {
		if window == nil || window.Warming || window.Seconds <= 0 {
			return severity(v, fiveMinuteCritical)
		}
		threshold := float64(fiveMinuteCritical) * window.Seconds / 300
		if float64(v) >= threshold {
			return "critical"
		}
		return "warning"
	}

	if a.Stack.SoftnetDropped > 0 {
		current := tunables["net.core.netdev_max_backlog"]
		add(models.KernelNetworkFinding{
			Severity: classify(a.Stack.SoftnetDropped, 1000), Layer: "softnet-backlog", Signal: "ingress backlog overflow",
			Evidence:       []string{fmt.Sprintf("softnet_dropped=%d", a.Stack.SoftnetDropped)},
			Explanation:    "Packets reached the host but the per-CPU network input backlog could not accept them. CPU saturation, IRQ imbalance, RPS placement, or a short ingress burst can cause this.",
			Recommendation: "First inspect per-CPU softnet deltas, IRQ affinity and CPU saturation. If bursts exceed a healthy CPU's momentary drain rate, canary a larger backlog; do not use it to mask sustained overload.",
			Tunable:        "net.core.netdev_max_backlog", SuggestedValue: doubledNumeric(current, 1_000, 65_536), Risk: "More queued packets consume memory and can increase queueing latency under sustained overload.",
		})
	}
	if a.Stack.SoftnetTimeSqueeze > 0 {
		current := tunables["net.core.netdev_budget_usecs"]
		add(models.KernelNetworkFinding{
			Severity: classify(a.Stack.SoftnetTimeSqueeze, 1000), Layer: "softnet-budget", Signal: "network softirq budget exhaustion",
			Evidence:       []string{fmt.Sprintf("softnet_time_squeeze=%d", a.Stack.SoftnetTimeSqueeze)},
			Explanation:    "NAPI/softirq processing repeatedly reached its packet or time budget while work remained.",
			Recommendation: "Inspect per-CPU softirq load, IRQ/RPS distribution and latency. If CPUs have headroom, canary a larger time budget; increasing it can starve other work on that CPU.",
			Tunable:        "net.core.netdev_budget_usecs", SuggestedValue: doubledNumeric(current, 2_000, 20_000), Risk: "A larger softirq budget can increase scheduling latency for applications and other kernel work.",
		})
	}
	if v := counters["TcpExt.TCPBacklogDrop"] + counters["TcpExt.TCPRcvQDrop"] + counters["TcpExt.TCPZeroWindowDrop"]; v > 0 {
		add(models.KernelNetworkFinding{
			Severity: classify(v, 1000), Layer: "tcp-receive", Signal: "TCP socket receive/backlog pressure",
			Evidence:       compactEvidence(fmtCount("TcpExt.TCPBacklogDrop", counters["TcpExt.TCPBacklogDrop"]), fmtCount("TcpExt.TCPRcvQDrop", counters["TcpExt.TCPRcvQDrop"]), fmtCount("TcpExt.TCPZeroWindowDrop", counters["TcpExt.TCPZeroWindowDrop"])),
			Explanation:    "TCP could not retain data in the socket receive/backlog path. A slow application reader, socket-lock contention, receive-memory pressure, or bursts can produce this signal.",
			Recommendation: "Find affected sockets with ss -tinm, inspect application read latency and cgroup memory, then canary application SO_RCVBUF/tcp_rmem changes. Netra does not guess a tcp_rmem vector without node RAM and socket-concurrency data.",
			Tunable:        "net.ipv4.tcp_rmem", Risk: "Larger per-socket receive buffers multiply memory use and can increase latency under overload.",
		})
	}
	if v := counters["Udp.RcvbufErrors"] + counters["Udp.MemErrors"]; v > 0 {
		current := tunables["net.core.rmem_max"]
		add(models.KernelNetworkFinding{
			Severity: classify(v, 1000), Layer: "socket-receive", Signal: "UDP receive buffer exhaustion",
			Evidence:       compactEvidence(fmtCount("Udp.RcvbufErrors", counters["Udp.RcvbufErrors"]), fmtCount("Udp.MemErrors", counters["Udp.MemErrors"])),
			Explanation:    "The UDP receive queue or protocol memory pool could not accept datagrams. A slow reader, bursty input, small SO_RCVBUF, or global memory pressure are common causes.",
			Recommendation: "Identify the socket with ss -u -m -p, fix slow consumers, then canary a larger application SO_RCVBUF and matching host ceiling.",
			Tunable:        "net.core.rmem_max", SuggestedValue: doubledNumeric(current, 262_144, 67_108_864), Risk: "Larger receive buffers multiply per-socket memory exposure and may delay overload detection.",
		})
	}
	if v := counters["Udp.SndbufErrors"]; v > 0 {
		current := tunables["net.core.wmem_max"]
		add(models.KernelNetworkFinding{
			Severity: classify(v, 1000), Layer: "socket-send", Signal: "UDP send buffer exhaustion",
			Evidence:       []string{fmt.Sprintf("Udp.SndbufErrors=%d", v)},
			Explanation:    "A UDP sender could not queue a datagram, usually because the application outpaced the qdisc/NIC or its send buffer was too small.",
			Recommendation: "Inspect socket memory and qdisc/NIC drops, rate-limit the producer, then canary SO_SNDBUF with a matching host ceiling.",
			Tunable:        "net.core.wmem_max", SuggestedValue: doubledNumeric(current, 262_144, 67_108_864), Risk: "Larger send buffers consume memory and can add latency while an egress bottleneck remains unresolved.",
		})
	}
	listen := counters["TcpExt.ListenDrops"] + counters["TcpExt.ListenOverflows"] + counters["TcpExt.TCPReqQFullDrop"] + counters["TcpExt.TCPDeferAcceptDrop"]
	if listen > 0 {
		current := tunables["net.core.somaxconn"]
		add(models.KernelNetworkFinding{
			Severity: classify(listen, 1000), Layer: "tcp-listen", Signal: "TCP accept/SYN queue overflow",
			Evidence:       compactEvidence(fmtCount("TcpExt.ListenDrops", counters["TcpExt.ListenDrops"]), fmtCount("TcpExt.ListenOverflows", counters["TcpExt.ListenOverflows"]), fmtCount("TcpExt.TCPReqQFullDrop", counters["TcpExt.TCPReqQFullDrop"]), fmtCount("TcpExt.TCPDeferAcceptDrop", counters["TcpExt.TCPDeferAcceptDrop"])),
			Explanation:    "Connection requests reached the node but a listening socket's completed accept queue or SYN request queue was full.",
			Recommendation: "Measure application accept latency and the listen backlog requested by the process. Scale/fix the accept loop before canarying larger somaxconn and tcp_max_syn_backlog values.",
			Tunable:        "net.core.somaxconn", SuggestedValue: doubledNumeric(current, 1_024, 65_535), Risk: "A larger queue consumes kernel memory and may turn immediate failure into higher connection latency.",
		})
	}
	memory := counters["TcpExt.TCPMemoryPressures"] + counters["TcpExt.TCPAbortOnMemory"] + counters["TcpExt.TCPWqueueTooBig"]
	if memory > 0 {
		add(models.KernelNetworkFinding{
			Severity: classify(memory, 100), Layer: "tcp-memory", Signal: "TCP memory pressure",
			Evidence:       compactEvidence(fmtCount("TcpExt.TCPMemoryPressures", counters["TcpExt.TCPMemoryPressures"]), fmtCount("TcpExt.TCPAbortOnMemory", counters["TcpExt.TCPAbortOnMemory"]), fmtCount("TcpExt.TCPWqueueTooBig", counters["TcpExt.TCPWqueueTooBig"])),
			Explanation:    "The TCP stack entered memory pressure or aborted/limited work because socket memory was unavailable.",
			Recommendation: "Check node memory, socket counts and cgroup memory limits. tcp_mem is expressed in pages and must be sized from node RAM and concurrency; Netra intentionally does not guess a value.",
			Tunable:        "net.ipv4.tcp_mem", Risk: "Blindly increasing tcp_mem can cause host-wide memory pressure or OOM events.",
		})
	}
	if v := counters["Tcp.RetransSegs"] + counters["Tcp.OutRsts"] + counters["Tcp.EstabResets"]; v > 0 {
		// fiveMinuteCritical=5000 is a first-pass placeholder, not a tuned
		// threshold — unlike the other counters this file already reads,
		// retransmits/resets are naturally noisy (a TCP slow-start alone
		// produces some) and need live-fleet baseline data before this
		// number is trustworthy. Deliberately no Tunable/ApplyCommand: there
		// is no safe buffer fix for retransmits or resets caused by real
		// packet loss, peer overload, or an application issuing its own
		// reset — same reasoning as the qdisc/ip branches below.
		add(models.KernelNetworkFinding{
			Severity: classify(v, 5000), Layer: "tcp-connection-quality", Signal: "TCP retransmits and resets",
			Evidence:       compactEvidence(fmtCount("Tcp.RetransSegs", counters["Tcp.RetransSegs"]), fmtCount("Tcp.OutRsts", counters["Tcp.OutRsts"]), fmtCount("Tcp.EstabResets", counters["Tcp.EstabResets"])),
			Explanation:    "TCP is retransmitting segments and/or resetting established connections more than expected. This can mean packet loss on the path, an overloaded or unresponsive peer, or an application-level abort pattern — not necessarily a kernel buffer limit.",
			Recommendation: "Correlate with ss -ti per-socket retransmit counts and Health/pathdiag RTT findings before treating this as a tunable problem — there is no dedicated buffer knob for retransmits or resets caused by real loss.",
			Risk:           "There is no safe buffer/tunable fix for retransmits or resets caused by real packet loss, peer overload, or application-issued resets; treating this as a buffer-sizing problem can mask the actual cause.",
		})
	}
	var qdiscDrops, rxMissed, ifaceDrops uint64
	for _, q := range a.QdiscStats {
		qdiscDrops += q.Drops
	}
	for _, it := range a.Stack.Interfaces {
		rxMissed += it.RXMissed
		ifaceDrops += it.RXDropped + it.TXDropped
	}
	if qdiscDrops > 0 {
		add(models.KernelNetworkFinding{
			Severity: classify(qdiscDrops, 1000), Layer: "qdisc", Signal: "egress queue drops", Evidence: []string{fmt.Sprintf("qdisc_drops=%d", qdiscDrops)},
			Explanation:    "The traffic-control queue discarded packets after the IP/socket stack. This can mean a configured queue limit, shaping/policing, or a producer faster than the NIC can drain.",
			Recommendation: "Inspect tc -s qdisc show and application pacing. Choose a qdisc and limits for the workload; changing socket buffers alone will not remove the egress bottleneck.",
			Risk:           "Increasing qdisc limits may create bufferbloat; changing qdisc algorithms can alter fairness and latency.",
		})
	}
	if max, ok := numericTunable(tunables["net.netfilter.nf_conntrack_max"]); ok && max > 0 && a.ConntrackEntries >= 0 {
		used := uint64(a.ConntrackEntries)
		if used*100 >= max*75 {
			sev := "warning"
			if used*100 >= max*90 {
				sev = "critical"
			}
			add(models.KernelNetworkFinding{
				Severity: sev, Layer: "conntrack", Signal: "conntrack table nearing capacity",
				Evidence:       []string{fmt.Sprintf("conntrack_entries=%d", used), fmt.Sprintf("nf_conntrack_max=%d", max), fmt.Sprintf("utilization_percent=%d", used*100/max)},
				Explanation:    "New tracked flows may fail when the conntrack table reaches its ceiling, affecting NAT and stateful filtering.",
				Recommendation: "Investigate flow churn and timeouts first. If the entry count is legitimate and memory is available, canary a larger table ceiling and monitor slab memory/hash performance.",
				Tunable:        "net.netfilter.nf_conntrack_max", SuggestedValue: strconv.FormatUint(max*2, 10), Risk: "Each conntrack entry consumes kernel memory; a larger table can materially increase host memory pressure.",
			})
		}
	}
	if rxMissed > 0 || ifaceDrops > 0 {
		add(models.KernelNetworkFinding{
			Severity: classify(rxMissed+ifaceDrops, 1000), Layer: "nic-driver", Signal: "interface receive/transmit loss",
			Evidence:       compactEvidence(fmtCount("rx_missed_errors", rxMissed), fmtCount("interface_rx_tx_dropped", ifaceDrops)),
			Explanation:    "Loss is visible at the device/driver layer, before or around the host stack. Ring exhaustion, IRQ/CPU imbalance, link errors, or virtual-device backpressure are likely.",
			Recommendation: "Inspect ethtool -S/-g, link counters, IRQ distribution and CPU pressure. Tune NIC rings/queues or vhost settings before raising protocol buffers.",
			Risk:           "Larger NIC rings consume DMA memory and can increase latency; unsupported ethtool changes may disrupt the interface.",
		})
	}
	if v := counters["Ip.InDiscards"] + counters["Ip.OutDiscards"] + counters["IpExt.InNoRoutes"] + counters["IpExt.OutNoRoutes"]; v > 0 {
		add(models.KernelNetworkFinding{
			Severity: classify(v, 1000), Layer: "ip", Signal: "IP-layer discard or route failure",
			Evidence:       compactEvidence(fmtCount("Ip.InDiscards", counters["Ip.InDiscards"]), fmtCount("Ip.OutDiscards", counters["Ip.OutDiscards"]), fmtCount("IpExt.InNoRoutes", counters["IpExt.InNoRoutes"]), fmtCount("IpExt.OutNoRoutes", counters["IpExt.OutNoRoutes"])),
			Explanation:    "Packets were discarded in the IP layer or no route was available. This is not necessarily a buffer problem.",
			Recommendation: "Correlate counter deltas with routes, policy, MTU/fragmentation, conntrack and Netra drop reasons before tuning any buffer.",
			Risk:           "Changing buffers without identifying the IP-layer cause can consume memory without reducing loss.",
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) > severityRank(out[j].Severity) })
	return out
}

func windowedAgent(a models.AgentStatus, w models.KernelNetworkWindow) models.AgentStatus {
	a.KernelNetwork.Counters = nil
	a.Stack = models.NodeStackStat{}
	a.QdiscStats = nil
	if w.Warming || w.Seconds <= 0 {
		return a
	}
	for _, c := range w.Counters {
		a.KernelNetwork.Counters = append(a.KernelNetwork.Counters, models.KernelNetworkCounter{Name: c.Name, Value: c.Delta, Source: "controller-window"})
	}
	a.Stack.SoftnetDropped = w.SoftnetDropped
	a.Stack.SoftnetTimeSqueeze = w.SoftnetTimeSqueeze
	if w.RXDropped > 0 || w.TXDropped > 0 || w.RXMissed > 0 {
		a.Stack.Interfaces = []models.InterfaceStackStat{{Name: "all", RXDropped: w.RXDropped, TXDropped: w.TXDropped, RXMissed: w.RXMissed}}
	}
	if w.QdiscDrops > 0 {
		a.QdiscStats = []models.QdiscStat{{Interface: "all", Kind: "all", Drops: w.QdiscDrops}}
	}
	return a
}

func doubledNumeric(raw string, floor, ceiling uint64) string {
	fields := strings.Fields(raw)
	if len(fields) != 1 {
		return ""
	}
	v, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return ""
	}
	if v >= ceiling {
		return ""
	}
	if v < floor {
		v = floor
	} else if v <= ceiling/2 {
		v *= 2
	} else {
		v = ceiling
	}
	return strconv.FormatUint(v, 10)
}

func numericTunable(raw string) (uint64, bool) {
	fields := strings.Fields(raw)
	if len(fields) != 1 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[0], 10, 64)
	return v, err == nil
}

func shellValue(v string) string {
	if strings.ContainsAny(v, " \t") {
		return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'"
	}
	return v
}

func fmtCount(name string, v uint64) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%s=%d", name, v)
}

func compactEvidence(items ...string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func severity(v, criticalAt uint64) string {
	if v >= criticalAt {
		return "critical"
	}
	return "warning"
}

func severityRank(v string) int {
	if v == "critical" {
		return 2
	}
	if v == "warning" {
		return 1
	}
	return 0
}

func findingScore(items []models.KernelNetworkFinding) int {
	score := 0
	for _, item := range items {
		score += severityRank(item.Severity)
	}
	return score
}
