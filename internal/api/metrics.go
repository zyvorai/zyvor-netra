// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"fmt"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	"github.com/zyvorai/netra/internal/dropdiag"
	"github.com/zyvorai/netra/internal/health"
	"github.com/zyvorai/netra/internal/histograms"
	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/kerneldiag"
	"github.com/zyvorai/netra/internal/l7"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/observability"
	"github.com/zyvorai/netra/internal/pathdiag"
)

type telemetry struct {
	requests           atomic.Uint64
	authFailures       atomic.Uint64
	mtlsRejected       atomic.Uint64
	mtlsReports        atomic.Uint64
	mtlsNodeMismatch   atomic.Uint64
	mtlsDeniedSerial   atomic.Uint64
	rbacDenied         atomic.Uint64
	policyPlans        atomic.Uint64
	policyApplies      atomic.Uint64
	policyDeletes      atomic.Uint64
	policyRollbacks    atomic.Uint64
	preflightRejects   atomic.Uint64
	agentReports       atomic.Uint64
	statePersistErrors atomic.Uint64
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	cfg := s.store.Config()
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	stale := 0
	resolvedWorkloads := 0
	var packets, bytes, blocked uint64
	for _, a := range agents {
		resolvedWorkloads += len(a.Workloads)
		if a.Stale {
			stale++
		}
		for _, st := range a.Stats {
			packets += st.Packets
			bytes += st.Bytes
			blocked += st.Blocked
		}
	}
	enforce := 0
	if cfg.Mode == "enforce" {
		enforce = 1
	}
	metricCounter(w, "netra_http_requests_total", "HTTP requests observed by netrad.", s.metricsData.requests.Load())
	metricCounter(w, "netra_auth_failures_total", "Rejected API or agent authentication attempts.", s.metricsData.authFailures.Load())
	metricCounter(w, "netra_agent_mtls_rejected_total", "Agent requests refused for lacking a verified client certificate (NETRA_AGENT_MTLS=required).", s.metricsData.mtlsRejected.Load())
	metricCounter(w, "netra_agent_mtls_reports_total", "Agent reports received over a connection with a verified client certificate.", s.metricsData.mtlsReports.Load())
	metricCounter(w, "netra_agent_mtls_node_mismatch_total", "Agent requests refused because the certificate node identity did not match the claimed node (NETRA_AGENT_MTLS_BIND_NODE).", s.metricsData.mtlsNodeMismatch.Load())
	metricCounter(w, "netra_agent_mtls_denied_serial_total", "Agent requests refused because the certificate serial is on NETRA_AGENT_MTLS_DENY_SERIALS.", s.metricsData.mtlsDeniedSerial.Load())
	metricCounter(w, "netra_rbac_denied_total", "Authenticated requests refused because the caller's role was too low.", s.metricsData.rbacDenied.Load())
	metricCounter(w, "netra_policy_plans_total", "Policy preflight plans requested.", s.metricsData.policyPlans.Load())
	metricCounter(w, "netra_policy_applies_total", "Non-dry-run CiliumNetworkPolicy applies.", s.metricsData.policyApplies.Load())
	metricCounter(w, "netra_policy_deletes_total", "CiliumNetworkPolicy deletes.", s.metricsData.policyDeletes.Load())
	metricCounter(w, "netra_policy_rollbacks_total", "CiliumNetworkPolicy rollbacks applied.", s.metricsData.policyRollbacks.Load())
	metricCounter(w, "netra_preflight_rejects_total", "Policy applies rejected due to a missing, stale or mismatched preflight receipt.", s.metricsData.preflightRejects.Load())
	metricCounter(w, "netra_agent_reports_total", "Node-agent reports accepted.", s.metricsData.agentReports.Load())
	metricCounter(w, "netra_state_persist_errors_total", "Durable state writes that failed after startup.", s.metricsData.statePersistErrors.Load())
	metricGauge(w, "netra_fastpath_enforce", "Whether Netra standalone eBPF enforcement is active.", float64(enforce))
	metricGauge(w, "netra_fastpath_blocked_ipv4", "Exact IPv4 destinations in the Netra deny map.", float64(len(cfg.BlockedIPv4)))
	metricGauge(w, "netra_fastpath_blocked_ipv6", "Exact IPv6 destinations in the Netra deny map.", float64(len(cfg.BlockedIPv6)))
	metricGauge(w, "netra_fastpath_blocked_cidrs", "Directional CIDR rules in the Netra datapath.", float64(len(cfg.BlockedCIDRs)))
	metricGauge(w, "netra_fastpath_blocked_ports", "Directional L4 port rules in the Netra datapath.", float64(len(cfg.BlockedPorts)))
	metricGauge(w, "netra_fastpath_blocked_uids", "UID socket-deny rules in the Netra datapath.", float64(len(cfg.BlockedUIDs)))
	metricGauge(w, "netra_fastpath_blocked_dns_names", "Exact cleartext DNS-name rules in the Netra datapath.", float64(len(cfg.BlockedDNS)))
	metricGauge(w, "netra_fastpath_blocked_processes", "Linux comm socket-deny rules in the Netra datapath.", float64(len(cfg.BlockedProcesses)))
	metricGauge(w, "netra_fastpath_blocked_sni_names", "Exact TLS SNI deny rules in the Netra datapath.", float64(len(cfg.BlockedSNI)))
	metricGauge(w, "netra_fastpath_rate_limits", "Exact IPv4/IPv6 destination PPS rules in the Netra datapath.", float64(len(cfg.RateLimits)))
	metricGauge(w, "netra_fastpath_allowed_ipv4", "Exact IPv4 allow-exceptions in the Netra datapath.", float64(len(cfg.AllowedIPv4)))
	metricGauge(w, "netra_fastpath_allowed_ipv6", "Exact IPv6 allow-exceptions in the Netra datapath.", float64(len(cfg.AllowedIPv6)))
	metricGauge(w, "netra_fastpath_allowed_cidrs", "Directional CIDR allow-exceptions in the Netra datapath.", float64(len(cfg.AllowedCIDRs)))
	metricGauge(w, "netra_fastpath_allowed_ports", "Directional L4 port allow-exceptions in the Netra datapath.", float64(len(cfg.AllowedPorts)))
	metricGauge(w, "netra_fastpath_blocked_ingress_ipv4", "Exact IPv4 ingress deny destinations.", float64(len(cfg.BlockedIngressIPv4)))
	metricGauge(w, "netra_fastpath_blocked_ingress_ipv6", "Exact IPv6 ingress deny destinations.", float64(len(cfg.BlockedIngressIPv6)))
	scopeSelected := 0
	if cfg.ScopeMode == "selected" {
		scopeSelected = 1
	}
	metricGauge(w, "netra_fastpath_scope_selected", "Whether enforcement is restricted to selected workload cgroups.", float64(scopeSelected))
	metricGauge(w, "netra_fastpath_workload_scopes", "Configured Kubernetes/cgroup enforcement scopes.", float64(len(cfg.WorkloadScopes)))
	metricGauge(w, "netra_workload_cgroups_resolved", "Kubernetes-looking cgroups resolved by node agents.", float64(resolvedWorkloads))
	metricGauge(w, "netra_agents_total", "Node agents known to the controller.", float64(len(agents)))
	metricGauge(w, "netra_agents_stale", "Node agents whose last report exceeded the stale threshold.", float64(stale))
	metricGauge(w, "netra_ebpf_packets", "Aggregate packet counter from the latest node reports.", float64(packets))
	metricGauge(w, "netra_ebpf_bytes", "Aggregate byte counter from the latest node reports.", float64(bytes))
	metricGauge(w, "netra_ebpf_blocked_packets", "Aggregate blocked-packet counter from the latest node reports.", float64(blocked))
	summary := observability.Summarize(agents, 10)
	metricGauge(w, "netra_ebpf_recent_events", "Recent standalone eBPF events retained in controller agent reports.", float64(summary.Events))
	metricGauge(w, "netra_ebpf_recent_dns_events", "Recent cleartext DNS query events retained in controller agent reports.", float64(summary.DNSQueries))
	metricGauge(w, "netra_ebpf_recent_socket_events", "Recent socket-context events retained in controller agent reports.", float64(summary.SocketEvents))
	healthSummary := health.Build(agents, 10).Summary
	metricGauge(w, "netra_tcp_connections", "TCP connections observed by the sockops health map.", float64(healthSummary.TCPConnections))
	metricGauge(w, "netra_tcp_retransmissions", "TCP retransmission callbacks observed by sockops.", float64(healthSummary.TCPRetransmissions))
	metricGauge(w, "netra_tcp_rtos", "TCP retransmission timeout callbacks observed by sockops.", float64(healthSummary.TCPRTOs))
	metricGauge(w, "netra_tcp_resets", "TCP packets carrying RST observed by cgroup packet hooks.", float64(healthSummary.TCPResets))
	metricGauge(w, "netra_tcp_average_srtt_us", "Weighted average smoothed TCP RTT in microseconds from sockops.", float64(healthSummary.AverageSRTTUS))
	metricGauge(w, "netra_tcp_max_srtt_us", "Maximum current smoothed TCP RTT in microseconds from sockops.", float64(healthSummary.MaxSRTTUS))
	metricGauge(w, "netra_dns_queries", "Cleartext UDP/53 DNS queries tracked by the standalone datapath.", float64(healthSummary.DNSQueries))
	metricGauge(w, "netra_dns_responses", "Cleartext UDP/53 DNS responses matched to tracked queries.", float64(healthSummary.DNSResponses))
	metricGauge(w, "netra_dns_failures", "Matched DNS responses with a non-zero DNS rcode.", float64(healthSummary.DNSFailures))
	metricGauge(w, "netra_dns_average_latency_us", "Average matched cleartext UDP/53 DNS response latency in microseconds.", float64(healthSummary.AverageDNSLatencyUS))
	metricGauge(w, "netra_dns_max_latency_us", "Maximum matched cleartext UDP/53 DNS response latency in microseconds.", float64(healthSummary.MaxDNSLatencyUS))
	metricGauge(w, "netra_connection_attempts", "Socket connect/sendmsg attempts observed by cgroup hooks.", float64(healthSummary.ConnectionAttempts))
	metricGauge(w, "netra_estimated_connect_failures", "Estimated TCP attempts not matched by active establishment counters; cumulative heuristic.", float64(healthSummary.EstimatedConnectFailures))
	metricGauge(w, "netra_network_health_score", "Deterministic 0-100 network health heuristic.", float64(healthSummary.HealthScore))
	dropSummary := dropdiag.Build(agents, 10).Summary
	metricGauge(w, "netra_kernel_skb_drops", "Cumulative skb:kfree_skb events reported by node agents when the tracepoint is available.", float64(dropSummary.KernelDropEvents))
	metricGauge(w, "netra_softnet_dropped", "Cumulative packets dropped by Linux softnet before protocol processing.", float64(dropSummary.SoftnetDropped))
	metricGauge(w, "netra_softnet_time_squeeze", "Cumulative softnet processing budget exhaustion events.", float64(dropSummary.SoftnetTimeSqueeze))
	metricGauge(w, "netra_interface_rx_dropped", "Aggregate interface receive dropped counters across fresh agents.", float64(dropSummary.RXDropped))
	metricGauge(w, "netra_interface_tx_dropped", "Aggregate interface transmit dropped counters across fresh agents.", float64(dropSummary.TXDropped))
	metricGauge(w, "netra_interface_rx_errors", "Aggregate interface receive error counters across fresh agents.", float64(dropSummary.RXErrors))
	metricGauge(w, "netra_interface_tx_errors", "Aggregate interface transmit error counters across fresh agents.", float64(dropSummary.TXErrors))
	metricGauge(w, "netra_interface_rx_missed", "Aggregate interface receive missed-error counters across fresh agents.", float64(dropSummary.RXMissed))
	metricGauge(w, "netra_interface_rx_nohandler", "Aggregate interface receive no-handler counters across fresh agents.", float64(dropSummary.RXNoHandler))
	metricGauge(w, "netra_qdisc_dropped", "Aggregate tc-qdisc drop counters (via netlink) across fresh agents, all interfaces/qdiscs combined.", float64(dropSummary.QdiscDrops))
	kernelWindows := s.store.KernelNetworkWindows(5 * time.Minute)
	kernelDiagnostics := kerneldiag.BuildWindow(agents, kernelWindows)
	var softnetDropRate, softnetSqueezeRate, rxDropRate, txDropRate, rxMissedRate, qdiscDropRate float64
	counterRates := map[string]float64{}
	for _, window := range kernelWindows {
		if window.Warming {
			continue
		}
		softnetDropRate += window.SoftnetDroppedRate
		softnetSqueezeRate += window.SoftnetSqueezeRate
		rxDropRate += window.RXDroppedRate
		txDropRate += window.TXDroppedRate
		rxMissedRate += window.RXMissedRate
		qdiscDropRate += window.QdiscDropsRate
		for _, counter := range window.Counters {
			counterRates[counter.Name] += counter.PerSecond
		}
	}
	metricGauge(w, "netra_kernel_network_findings", "Evidence-backed kernel network findings over the current five-minute window.", float64(kernelDiagnostics.Summary.Findings))
	metricGauge(w, "netra_kernel_network_critical_findings", "Critical kernel network findings over the current five-minute window.", float64(kernelDiagnostics.Summary.Critical))
	metricGauge(w, "netra_kernel_network_warning_findings", "Warning kernel network findings over the current five-minute window.", float64(kernelDiagnostics.Summary.Warnings))
	metricGauge(w, "netra_kernel_network_warming_nodes", "Nodes without two same-process reports for kernel network delta analytics.", float64(kernelDiagnostics.Summary.Warming))
	metricGaugeFloat(w, "netra_softnet_drop_rate", "Linux softnet drops per second over the current five-minute window.", softnetDropRate)
	metricGaugeFloat(w, "netra_softnet_time_squeeze_rate", "Linux softnet budget exhaustions per second over the current five-minute window.", softnetSqueezeRate)
	metricGaugeFloat(w, "netra_interface_rx_drop_rate", "Aggregate interface receive drops per second over the current five-minute window.", rxDropRate)
	metricGaugeFloat(w, "netra_interface_tx_drop_rate", "Aggregate interface transmit drops per second over the current five-minute window.", txDropRate)
	metricGaugeFloat(w, "netra_interface_rx_missed_rate", "Aggregate interface receive missed packets per second over the current five-minute window.", rxMissedRate)
	metricGaugeFloat(w, "netra_qdisc_drop_rate", "Aggregate qdisc drops per second over the current five-minute window.", qdiscDropRate)
	metricGaugeFloat(w, "netra_udp_receive_buffer_error_rate", "UDP receive-buffer errors per second over the current five-minute window.", counterRates["Udp.RcvbufErrors"])
	metricGaugeFloat(w, "netra_udp_send_buffer_error_rate", "UDP send-buffer errors per second over the current five-minute window.", counterRates["Udp.SndbufErrors"])
	metricGaugeFloat(w, "netra_tcp_listen_drop_rate", "TCP listen and request-queue drops per second over the current five-minute window.", counterRates["TcpExt.ListenDrops"]+counterRates["TcpExt.ListenOverflows"]+counterRates["TcpExt.TCPReqQFullDrop"]+counterRates["TcpExt.TCPDeferAcceptDrop"])
	metricGaugeFloat(w, "netra_tcp_receive_queue_drop_rate", "TCP receive/backlog drops per second over the current five-minute window.", counterRates["TcpExt.TCPBacklogDrop"]+counterRates["TcpExt.TCPRcvQDrop"]+counterRates["TcpExt.TCPZeroWindowDrop"])
	metricGaugeFloat(w, "netra_tcp_memory_pressure_rate", "TCP memory-pressure events per second over the current five-minute window.", counterRates["TcpExt.TCPMemoryPressures"]+counterRates["TcpExt.TCPAbortOnMemory"]+counterRates["TcpExt.TCPWqueueTooBig"])
	metricGaugeFloat(w, "netra_ip_discard_rate", "IP-layer discards and no-route events per second over the current five-minute window.", counterRates["Ip.InDiscards"]+counterRates["Ip.OutDiscards"]+counterRates["IpExt.InNoRoutes"]+counterRates["IpExt.OutNoRoutes"])
	pathSummary := pathdiag.Build(agents, 10).Summary
	metricGauge(w, "netra_tcp_connect_established_measured", "TCP active establishments with connect latency measured by Netra.", float64(pathSummary.ConnectionsMeasured))
	metricGauge(w, "netra_tcp_connect_average_latency_us", "Average measured TCP active connect establishment latency in microseconds.", float64(pathSummary.AverageConnectUS))
	metricGauge(w, "netra_tcp_connect_max_latency_us", "Maximum measured TCP active connect establishment latency in microseconds.", float64(pathSummary.MaxConnectUS))
	metricGauge(w, "netra_tcp_packets_out", "Current aggregate TCP packets_out from sockops path diagnostics.", float64(pathSummary.PacketsOut))
	metricGauge(w, "netra_tcp_retrans_out", "Current aggregate retransmitted TCP segments outstanding.", float64(pathSummary.RetransOut))
	metricGauge(w, "netra_tcp_lost_out", "Current aggregate TCP segments marked lost by the kernel.", float64(pathSummary.LostOut))
	metricGauge(w, "netra_tcp_total_retrans", "Aggregate kernel total_retrans snapshots across reported sockets.", float64(pathSummary.TotalRetrans))
	metricGauge(w, "netra_tcp_cwnd_pressure_flows", "TCP flows with packets_out at least 80 percent of snd_cwnd.", float64(pathSummary.CongestedFlows))
	l7s := l7.Build(agents, 10).Summary
	metricGauge(w, "netra_tls_sni_handshakes", "Best-effort TLS ClientHello records with parsed SNI.", float64(l7s.TLSHandshakes))
	metricGauge(w, "netra_tls_sni_blocked", "Best-effort TLS ClientHello records blocked by exact SNI rules.", float64(l7s.TLSBlocked))
	metricGauge(w, "netra_http1_requests", "Best-effort cleartext HTTP/1 requests with parsed Host metadata.", float64(l7s.HTTPRequests))
	metricGauge(w, "netra_http1_status_5xx", "Cleartext HTTP/1 responses whose status line started the packet and was 500-599. No HTTP/2 or HTTP/3.", float64(l7s.HTTP5xx))
	metricGauge(w, "netra_l7_unique_sni", "Unique parsed TLS SNI names in latest node maps.", float64(l7s.UniqueSNI))
	metricGauge(w, "netra_l7_unique_http_hosts", "Unique parsed cleartext HTTP Host values in latest node maps.", float64(l7s.UniqueHTTPHosts))
	baseline := s.store.Baseline()
	drift := insights.Drift(baseline, agents)
	metricGauge(w, "netra_behavior_baseline_entries", "Known-good behavior entries in the persisted Netra baseline.", float64(len(baseline.Entries)))
	metricGauge(w, "netra_behavior_drift_findings", "Current behaviors not present in the persisted baseline and above noise thresholds.", float64(len(drift.Findings)))
	rateWindow := s.store.RateWindow(5*time.Minute, time.Now())
	rateBaseline := s.store.RateBaseline()
	rateDrift := insights.RateDrift(rateBaseline, rateWindow)
	warming := 0
	if rateWindow.Warming {
		warming = 1
	}
	metricGauge(w, "netra_rate_window_warming", "Whether the controller lacks two fresh agent reports for delta-based rate analytics.", float64(warming))
	metricGauge(w, "netra_rate_baseline_entries", "Persisted traffic-rate baseline metric entries.", float64(len(rateBaseline.Entries)))
	metricGauge(w, "netra_rate_drift_findings", "Current delta-based traffic-rate anomalies above baseline thresholds.", float64(len(rateDrift.Findings)))
	metricGauge(w, "netra_dependency_edges", "Workload egress dependency edges derived from exact standalone eBPF counters before Kubernetes service resolution.", float64(len(observability.Topology(agents, 5000))))

	writeNetworkHistograms(w, agents)
	writeProgramHealth(w, agents)
	metricGauge(w, "netra_flowlog_records", "In-memory flow-history records on this controller. No pod or destination labels.", float64(s.store.FlowCount()))
	writeTCPEventMetrics(w, agents)
	writeDropInfoMetrics(w, agents)
	writeListenQueueMetrics(w, agents)
	writeNetlinkMetrics(w, agents)
	writeBPFAttachMetrics(w, agents)
	writeMapScanMetrics(w, agents)
	writeL7SampleMetrics(w, agents)
	writeTLSSampleMetrics(w, agents)
	s.writeWorkloadMetrics(w)
}

func writeNetworkHistograms(w http.ResponseWriter, agents []models.AgentStatus) {
	var retrans, srtt, connect []histograms.Snapshot
	var listenOverflows, listenDrops, softirq uint64
	for _, a := range agents {
		if a.Stale || a.Histograms == nil {
			continue
		}
		h := a.Histograms
		retrans = append(retrans, histograms.Snapshot{
			Name: h.TCPRetransmissions.Name, Bounds: h.TCPRetransmissions.Bounds,
			CumulativeCounts: h.TCPRetransmissions.CumulativeCounts, Sum: h.TCPRetransmissions.Sum, Count: h.TCPRetransmissions.Count,
		})
		srtt = append(srtt, histograms.Snapshot{
			Name: h.TCPSRTTUS.Name, Bounds: h.TCPSRTTUS.Bounds,
			CumulativeCounts: h.TCPSRTTUS.CumulativeCounts, Sum: h.TCPSRTTUS.Sum, Count: h.TCPSRTTUS.Count,
		})
		connect = append(connect, histograms.Snapshot{
			Name: h.TCPConnectUS.Name, Bounds: h.TCPConnectUS.Bounds,
			CumulativeCounts: h.TCPConnectUS.CumulativeCounts, Sum: h.TCPConnectUS.Sum, Count: h.TCPConnectUS.Count,
		})
		listenOverflows += h.Host.ListenOverflows
		listenDrops += h.Host.ListenDrops
		softirq += h.Host.SoftirqNETRX
	}
	metricHistogram(w, "netra_tcp_retransmissions", "Per-flow TCP retransmission counts from sockops health snapshots.", histograms.Merge(retrans...))
	metricHistogram(w, "netra_tcp_srtt_us", "Per-flow smoothed TCP RTT in microseconds from sockops.", histograms.Merge(srtt...))
	metricHistogram(w, "netra_tcp_connect_us", "Average measured TCP connect-establishment latency in microseconds.", histograms.Merge(connect...))
	metricGauge(w, "netra_tcp_listen_overflows", "Kernel TcpExt ListenOverflows summed across fresh agents.", float64(listenOverflows))
	metricGauge(w, "netra_tcp_listen_drops", "Kernel TcpExt ListenDrops summed across fresh agents.", float64(listenDrops))
	metricGauge(w, "netra_softirq_net_rx", "Cumulative softirq NET_RX counts summed across fresh agents.", float64(softirq))
}

func writeProgramHealth(w http.ResponseWriter, agents []models.AgentStatus) {
	type agg struct {
		attached int
		nodes    int
		runs     uint64
		runtime  uint64
	}
	byName := map[string]*agg{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, p := range a.Programs {
			x := byName[p.Name]
			if x == nil {
				x = &agg{}
				byName[p.Name] = x
			}
			x.nodes++
			if p.Attached {
				x.attached++
			}
			x.runs += p.RunCount
			x.runtime += p.RunTimeNS
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 0 {
		fmt.Fprintf(w, "# HELP netra_ebpf_program_attached Whether a Netra BPF program is attached on a reporting node (1=yes).\n# TYPE netra_ebpf_program_attached gauge\n")
		for _, n := range names {
			x := byName[n]
			v := 0.0
			if x.attached > 0 {
				v = float64(x.attached) / float64(x.nodes)
			}
			fmt.Fprintf(w, "netra_ebpf_program_attached{program=%q} %.4f\n", n, v)
		}
		fmt.Fprintf(w, "# HELP netra_ebpf_program_run_count_total Cumulative BPF program run counts from kernel stats when available.\n# TYPE netra_ebpf_program_run_count_total counter\n")
		for _, n := range names {
			fmt.Fprintf(w, "netra_ebpf_program_run_count_total{program=%q} %d\n", n, byName[n].runs)
		}
		fmt.Fprintf(w, "# HELP netra_ebpf_program_run_time_seconds_total Cumulative BPF program runtime from kernel stats when available.\n# TYPE netra_ebpf_program_run_time_seconds_total counter\n")
		for _, n := range names {
			fmt.Fprintf(w, "netra_ebpf_program_run_time_seconds_total{program=%q} %.9f\n", n, float64(byName[n].runtime)/1e9)
		}
	}
}

func metricHistogram(w http.ResponseWriter, name, help string, s histograms.Snapshot) {
	if s.Count == 0 && len(s.CumulativeCounts) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for i, le := range s.Bounds {
		c := uint64(0)
		if i < len(s.CumulativeCounts) {
			c = s.CumulativeCounts[i]
		}
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, le, c)
	}
	inf := uint64(0)
	if len(s.CumulativeCounts) > 0 {
		inf = s.CumulativeCounts[len(s.CumulativeCounts)-1]
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, inf)
	fmt.Fprintf(w, "%s_sum %.0f\n", name, s.Sum)
	fmt.Fprintf(w, "%s_count %d\n", name, s.Count)
}

func metricCounter(w http.ResponseWriter, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
}
func metricGauge(w http.ResponseWriter, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %.0f\n", name, help, name, name, value)
}

func metricGaugeFloat(w http.ResponseWriter, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %.6f\n", name, help, name, name, value)
}
