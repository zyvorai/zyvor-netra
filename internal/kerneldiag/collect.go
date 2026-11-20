// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package kerneldiag collects read-only Linux networking tunables and drop
// counters. It intentionally does not write sysctls: production tuning needs
// workload evidence, a canary, and an operator-owned rollback.
package kerneldiag

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Tunables covers the buffers, packet-processing budgets, listen queues and
// TCP/UDP memory controls most often involved in host-network packet loss.
// Missing files are normal across kernel versions and are simply omitted.
var Tunables = []string{
	"net.core.netdev_max_backlog",
	"net.core.netdev_budget",
	"net.core.netdev_budget_usecs",
	"net.core.dev_weight",
	"net.core.rmem_default",
	"net.core.rmem_max",
	"net.core.wmem_default",
	"net.core.wmem_max",
	"net.core.optmem_max",
	"net.core.somaxconn",
	"net.core.rps_sock_flow_entries",
	"net.core.flow_limit_table_len",
	"net.core.busy_poll",
	"net.core.busy_read",
	"net.core.default_qdisc",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
	"net.ipv4.tcp_mem",
	"net.ipv4.tcp_max_syn_backlog",
	"net.ipv4.tcp_moderate_rcvbuf",
	"net.ipv4.tcp_adv_win_scale",
	"net.ipv4.tcp_limit_output_bytes",
	"net.ipv4.tcp_notsent_lowat",
	"net.ipv4.tcp_congestion_control",
	"net.ipv4.tcp_available_congestion_control",
	"net.ipv4.udp_rmem_min",
	"net.ipv4.udp_wmem_min",
	"net.ipv4.udp_mem",
	"net.ipv4.ip_local_port_range",
	"net.netfilter.nf_conntrack_max",
}

var wantedCounters = map[string]map[string]struct{}{
	"Ip":    set("InDiscards", "OutDiscards", "InHdrErrors", "InAddrErrors", "ReasmFails", "FragFails"),
	"Tcp":   set("RetransSegs", "InErrs", "OutRsts", "AttemptFails", "EstabResets"),
	"Udp":   set("NoPorts", "InErrors", "RcvbufErrors", "SndbufErrors", "IgnoredMulti", "MemErrors"),
	"IpExt": set("InNoRoutes", "InTruncatedPkts", "InCsumErrors", "OutNoRoutes"),
	"TcpExt": set(
		"ListenDrops", "ListenOverflows", "TCPBacklogDrop", "TCPRcvQDrop",
		"TCPZeroWindowDrop", "TCPDeferAcceptDrop",
		"TCPMemoryPressures", "TCPMemoryPressuresChrono", "TCPAbortOnMemory",
		"TCPWqueueTooBig", "TCPSynRetrans", "TCPTimeouts", "TCPLostRetransmit",
		"TCPFastOpenListenOverflow", "TCPReqQFullDrop", "TCPReqQFullDoCookies",
	),
}

func set(names ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, name := range names {
		out[name] = struct{}{}
	}
	return out
}

// Collect reads from root, which is "/" in production and a temporary fixture
// in tests. All errors are best-effort: a restricted container should still
// report the subset mounted into its namespace.
func Collect(root string) models.KernelNetworkSnapshot {
	if root == "" {
		root = "/"
	}
	out := models.KernelNetworkSnapshot{}
	for _, name := range Tunables {
		path := filepath.Join(root, "proc/sys", strings.ReplaceAll(name, ".", "/"))
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		out.Tunables = append(out.Tunables, models.KernelTunable{
			Name: name, Value: strings.Join(strings.Fields(string(b)), " "), Source: "/proc/sys/" + strings.ReplaceAll(name, ".", "/"),
		})
	}
	for _, rel := range []string{"proc/net/snmp", "proc/net/netstat"} {
		out.Counters = append(out.Counters, parseCounters(filepath.Join(root, rel), "/"+rel)...)
	}
	sort.Slice(out.Counters, func(i, j int) bool { return out.Counters[i].Name < out.Counters[j].Name })
	return out
}

func parseCounters(path, source string) []models.KernelNetworkCounter {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(b), "\n")
	var out []models.KernelNetworkCounter
	for i := 0; i+1 < len(lines); i++ {
		head, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if len(head) < 2 || len(values) != len(head) || head[0] != values[0] || !strings.HasSuffix(head[0], ":") {
			continue
		}
		group := strings.TrimSuffix(head[0], ":")
		wanted, ok := wantedCounters[group]
		if !ok {
			continue
		}
		for n := 1; n < len(head); n++ {
			if _, ok := wanted[head[n]]; !ok {
				continue
			}
			v, err := strconv.ParseUint(values[n], 10, 64)
			if err != nil {
				continue
			}
			out = append(out, models.KernelNetworkCounter{Name: group + "." + head[n], Value: v, Source: source})
		}
		i++
	}
	return out
}
