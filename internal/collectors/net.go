// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------- /proc/net/dev

// NetDev reads per-interface counters from /proc/net/dev plus sysfs state.
// net.operstate is charted only for interfaces seen up since the agent
// started, so idle bridges and unplugged ports never read as an outage.
type NetDev struct {
	fs     fsys
	seenUp map[string]bool
}

func (*NetDev) Info() Info { return Info{Name: "proc.net.dev", Family: "net"} }

func (n *NetDev) Collect(_ time.Time, e *Emitter) error {
	lines, err := readLines(n.fs.procPath("net", "dev"))
	if err != nil {
		return err
	}
	if n.seenUp == nil {
		n.seenUp = map[string]bool{}
	}
	present := map[string]bool{}
	var rxAll, txAll float64
	for _, l := range lines {
		name, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		iface := strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 16 {
			continue
		}
		virtual := "false"
		if _, err := os.Stat(n.fs.sysPath("devices", "virtual", "net", iface)); err == nil {
			virtual = "true"
		}
		lbl := map[string]string{"interface": iface, "virtual": virtual}
		rxB, rxP, rxErr, rxDrop, rxFifo, rxFrame, rxMcast := pf(f[0]), pf(f[1]), pf(f[2]), pf(f[3]), pf(f[4]), pf(f[5]), pf(f[7])
		txB, txP, txErr, txDrop, txFifo, txColl, txCarrier := pf(f[8]), pf(f[9]), pf(f[10]), pf(f[11]), pf(f[12]), pf(f[13]), pf(f[14])
		bw := Chart{Context: "net.net", ID: "net." + iface, Family: "net", Units: "kilobits/s", Title: "Bandwidth", Type: "area", Labels: lbl}
		e.Incremental(bw, "received", rxB, 8.0/1000)
		e.Incremental(bw, "sent", txB, 8.0/1000)
		pk := Chart{Context: "net.packets", ID: "net_packets." + iface, Family: "net", Units: "packets/s", Title: "Packets", Labels: lbl}
		e.Incremental(pk, "received", rxP, 1)
		e.Incremental(pk, "sent", txP, 1)
		e.Incremental(pk, "multicast", rxMcast, 1)
		er := Chart{Context: "net.errors", ID: "net_errors." + iface, Family: "net", Units: "errors/s", Title: "Interface errors", Labels: lbl}
		e.Incremental(er, "inbound", rxErr, 1)
		e.Incremental(er, "outbound", txErr, 1)
		dr := Chart{Context: "net.drops", ID: "net_drops." + iface, Family: "net", Units: "drops/s", Title: "Interface drops", Labels: lbl}
		e.Incremental(dr, "inbound", rxDrop, 1)
		e.Incremental(dr, "outbound", txDrop, 1)
		ff := Chart{Context: "net.fifo", ID: "net_fifo." + iface, Family: "net", Units: "errors/s", Title: "Interface FIFO buffer errors", Labels: lbl}
		e.Incremental(ff, "receive", rxFifo, 1)
		e.Incremental(ff, "transmit", txFifo, 1)
		e.Incremental(Chart{Context: "net.frames", ID: "net_frames." + iface, Family: "net", Units: "frames/s", Title: "Interface frame errors", Labels: lbl}, "frames", rxFrame, 1)
		e.Incremental(Chart{Context: "net.carrier", ID: "net_carrier." + iface, Family: "net", Units: "events/s", Title: "Interface carrier and collision events", Labels: lbl}, "carrier", txCarrier, 1)
		e.Incremental(Chart{Context: "net.carrier", ID: "net_carrier." + iface, Family: "net", Units: "events/s", Title: "Interface carrier and collision events", Labels: lbl}, "collisions", txColl, 1)
		if v, ok := readFloat(n.fs.sysPath("class", "net", iface, "speed")); ok && v > 0 {
			e.Gauge(Chart{Context: "net.speed", ID: "net_speed." + iface, Family: "net", Units: "kilobits/s", Title: "Interface speed", Labels: lbl}, "speed", v*1000)
		}
		if v, ok := readFloat(n.fs.sysPath("class", "net", iface, "mtu")); ok {
			e.Gauge(Chart{Context: "net.mtu", ID: "net_mtu." + iface, Family: "net", Units: "octets", Title: "Interface MTU", Labels: lbl}, "mtu", v)
		}
		if s, err := readTrim(n.fs.sysPath("class", "net", iface, "operstate")); err == nil {
			up := 0.0
			if s == "up" || s == "unknown" {
				up = 1
				n.seenUp[iface] = true
			}
			present[iface] = true
			if n.seenUp[iface] {
				e.Gauge(Chart{Context: "net.operstate", ID: "net_operstate." + iface, Family: "net", Units: "state", Title: "Interface operational state (1 up)", Labels: lbl}, "up", up)
			}
		}
		if virtual == "false" {
			rxAll += rxB
			txAll += txB
		}
	}
	for iface := range n.seenUp {
		if !present[iface] {
			delete(n.seenUp, iface)
		}
	}
	sys := Chart{Context: "system.net", Family: "net", Units: "kilobits/s", Title: "Physical network interfaces aggregated bandwidth", Type: "area"}
	e.Incremental(sys, "received", rxAll, 8.0/1000)
	e.Incremental(sys, "sent", txAll, 8.0/1000)
	return nil
}

// ---------------------------------------------------------------- /proc/net/snmp

// SNMP reads IPv4 IP, ICMP, TCP and UDP counters plus IPv6 basics.
type SNMP struct{ fs fsys }

func (*SNMP) Info() Info { return Info{Name: "proc.net.snmp", Family: "ip"} }

func (s *SNMP) Collect(_ time.Time, e *Emitter) error {
	m, err := headerPairs(s.fs.procPath("net", "snmp"))
	if err != nil {
		return err
	}
	ip := m["Ip"]
	pk := Chart{Context: "ipv4.packets", Family: "ipv4", Units: "packets/s", Title: "IPv4 packets"}
	e.Incremental(pk, "received", ip["InReceives"], 1)
	e.Incremental(pk, "sent", ip["OutRequests"], 1)
	e.Incremental(pk, "forwarded", ip["ForwDatagrams"], 1)
	e.Incremental(pk, "delivered", ip["InDelivers"], 1)
	ie := Chart{Context: "ipv4.errors", Family: "ipv4", Units: "packets/s", Title: "IPv4 errors"}
	e.Incremental(ie, "InDiscards", ip["InDiscards"], 1)
	e.Incremental(ie, "OutDiscards", ip["OutDiscards"], 1)
	e.Incremental(ie, "InHdrErrors", ip["InHdrErrors"], 1)
	e.Incremental(ie, "OutNoRoutes", ip["OutNoRoutes"], 1)
	e.Incremental(ie, "InAddrErrors", ip["InAddrErrors"], 1)
	e.Incremental(ie, "InUnknownProtos", ip["InUnknownProtos"], 1)

	ic := m["Icmp"]
	icp := Chart{Context: "ipv4.icmp", Family: "icmp", Units: "packets/s", Title: "IPv4 ICMP packets"}
	e.Incremental(icp, "received", ic["InMsgs"], 1)
	e.Incremental(icp, "sent", ic["OutMsgs"], 1)
	ice := Chart{Context: "ipv4.icmp_errors", Family: "icmp", Units: "packets/s", Title: "IPv4 ICMP errors"}
	e.Incremental(ice, "InErrors", ic["InErrors"], 1)
	e.Incremental(ice, "OutErrors", ic["OutErrors"], 1)
	e.Incremental(ice, "InCsumErrors", ic["InCsumErrors"], 1)

	tcp := m["Tcp"]
	e.Gauge(Chart{Context: "ipv4.tcpsock", Family: "tcp", Units: "active connections", Title: "IPv4 TCP connections"}, "connections", tcp["CurrEstab"])
	tp := Chart{Context: "ipv4.tcppackets", Family: "tcp", Units: "packets/s", Title: "IPv4 TCP packets"}
	e.Incremental(tp, "received", tcp["InSegs"], 1)
	e.Incremental(tp, "sent", tcp["OutSegs"], 1)
	te := Chart{Context: "ipv4.tcperrors", Family: "tcp", Units: "packets/s", Title: "IPv4 TCP errors"}
	e.Incremental(te, "InErrs", tcp["InErrs"], 1)
	e.Incremental(te, "InCsumErrors", tcp["InCsumErrors"], 1)
	e.Incremental(te, "RetransSegs", tcp["RetransSegs"], 1)
	if out := tcp["OutSegs"]; out > 0 {
		e.Incremental(Chart{Context: "ipv4.tcp_retrans_segments", Family: "tcp", Units: "segments/s", Title: "IPv4 TCP retransmitted segments"}, "retransmits", tcp["RetransSegs"], 1)
	}
	to := Chart{Context: "ipv4.tcpopens", Family: "tcp", Units: "connections/s", Title: "IPv4 TCP opens"}
	e.Incremental(to, "active", tcp["ActiveOpens"], 1)
	e.Incremental(to, "passive", tcp["PassiveOpens"], 1)
	th := Chart{Context: "ipv4.tcphandshake", Family: "tcp", Units: "events/s", Title: "IPv4 TCP handshake issues"}
	e.Incremental(th, "EstabResets", tcp["EstabResets"], 1)
	e.Incremental(th, "OutRsts", tcp["OutRsts"], 1)
	e.Incremental(th, "AttemptFails", tcp["AttemptFails"], 1)

	udp := m["Udp"]
	up := Chart{Context: "ipv4.udppackets", Family: "udp", Units: "packets/s", Title: "IPv4 UDP packets"}
	e.Incremental(up, "received", udp["InDatagrams"], 1)
	e.Incremental(up, "sent", udp["OutDatagrams"], 1)
	ue := Chart{Context: "ipv4.udperrors", Family: "udp", Units: "events/s", Title: "IPv4 UDP errors"}
	for _, k := range []string{"RcvbufErrors", "SndbufErrors", "InErrors", "NoPorts", "InCsumErrors", "IgnoredMulti"} {
		e.Incremental(ue, k, udp[k], 1)
	}

	if v6, err := keyValueFile(s.fs.procPath("net", "snmp6")); err == nil {
		p6 := Chart{Context: "ipv6.packets", Family: "ipv6", Units: "packets/s", Title: "IPv6 packets"}
		e.Incremental(p6, "received", v6["Ip6InReceives"], 1)
		e.Incremental(p6, "sent", v6["Ip6OutRequests"], 1)
		e.Incremental(p6, "forwarded", v6["Ip6OutForwDatagrams"], 1)
		e.Incremental(p6, "delivered", v6["Ip6InDelivers"], 1)
		e6 := Chart{Context: "ipv6.errors", Family: "ipv6", Units: "packets/s", Title: "IPv6 errors"}
		for _, k := range []string{"Ip6InDiscards", "Ip6OutDiscards", "Ip6InHdrErrors", "Ip6InNoRoutes", "Ip6OutNoRoutes", "Ip6InAddrErrors"} {
			e.Incremental(e6, strings.TrimPrefix(k, "Ip6"), v6[k], 1)
		}
		u6 := Chart{Context: "ipv6.udppackets", Family: "udp6", Units: "packets/s", Title: "IPv6 UDP packets"}
		e.Incremental(u6, "received", v6["Udp6InDatagrams"], 1)
		e.Incremental(u6, "sent", v6["Udp6OutDatagrams"], 1)
		i6 := Chart{Context: "ipv6.icmp", Family: "icmp6", Units: "messages/s", Title: "IPv6 ICMP messages"}
		e.Incremental(i6, "received", v6["Icmp6InMsgs"], 1)
		e.Incremental(i6, "sent", v6["Icmp6OutMsgs"], 1)
	}
	return nil
}

// ---------------------------------------------------------------- /proc/net/netstat

// Netstat reads TcpExt and IpExt extended counters.
type Netstat struct{ fs fsys }

func (*Netstat) Info() Info { return Info{Name: "proc.net.netstat", Family: "tcp"} }

func (n *Netstat) Collect(_ time.Time, e *Emitter) error {
	m, err := headerPairs(n.fs.procPath("net", "netstat"))
	if err != nil {
		return err
	}
	t := m["TcpExt"]
	l := Chart{Context: "ip.tcp_accept_queue", Family: "tcp", Units: "packets/s", Title: "TCP accept queue issues"}
	e.Incremental(l, "overflows", t["ListenOverflows"], 1)
	e.Incremental(l, "drops", t["ListenDrops"], 1)
	sc := Chart{Context: "ip.tcp_syn_queue", Family: "tcp", Units: "packets/s", Title: "TCP SYN queue issues"}
	e.Incremental(sc, "drops", t["TCPReqQFullDrop"], 1)
	e.Incremental(sc, "cookies", t["TCPReqQFullDoCookies"], 1)
	ck := Chart{Context: "ip.tcpsyncookies", Family: "tcp", Units: "packets/s", Title: "TCP SYN cookies"}
	e.Incremental(ck, "received", t["SyncookiesRecv"], 1)
	e.Incremental(ck, "sent", t["SyncookiesSent"], 1)
	e.Incremental(ck, "failed", t["SyncookiesFailed"], 1)
	ab := Chart{Context: "ip.tcpconnaborts", Family: "tcp", Units: "connections/s", Title: "TCP connection aborts"}
	e.Incremental(ab, "baddata", t["TCPAbortOnData"], 1)
	e.Incremental(ab, "userclosed", t["TCPAbortOnClose"], 1)
	e.Incremental(ab, "nomemory", t["TCPAbortOnMemory"], 1)
	e.Incremental(ab, "timeout", t["TCPAbortOnTimeout"], 1)
	e.Incremental(ab, "linger", t["TCPAbortOnLinger"], 1)
	e.Incremental(ab, "failed", t["TCPAbortFailed"], 1)
	rt := Chart{Context: "ip.tcp_retransmits", Family: "tcp", Units: "events/s", Title: "TCP retransmission events"}
	e.Incremental(rt, "timeouts", t["TCPTimeouts"], 1)
	e.Incremental(rt, "fast", t["TCPFastRetrans"], 1)
	e.Incremental(rt, "slow_start", t["TCPSlowStartRetrans"], 1)
	e.Incremental(rt, "lost", t["TCPLostRetransmit"], 1)
	e.Incremental(rt, "syn", t["TCPSynRetrans"], 1)
	ro := Chart{Context: "ip.tcpreorders", Family: "tcp", Units: "packets/s", Title: "TCP reordered packets by detection method"}
	for _, k := range []string{"TCPTSReorder", "TCPSACKReorder", "TCPRenoReorder"} {
		e.Incremental(ro, strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(k, "TCP"), "Reorder")), t[k], 1)
	}
	of := Chart{Context: "ip.tcpofo", Family: "tcp", Units: "packets/s", Title: "TCP out-of-order queue"}
	e.Incremental(of, "inqueue", t["TCPOFOQueue"], 1)
	e.Incremental(of, "dropped", t["TCPOFODrop"], 1)
	e.Incremental(of, "merged", t["TCPOFOMerge"], 1)
	e.Incremental(Chart{Context: "ip.tcp_memory_pressure", Family: "tcp", Units: "events/s", Title: "TCP memory pressure events"}, "pressures", t["TCPMemoryPressures"], 1)
	e.Incremental(Chart{Context: "ip.tcp_backlog_drops", Family: "tcp", Units: "packets/s", Title: "TCP backlog queue drops"}, "drops", t["TCPBacklogDrop"], 1)

	x := m["IpExt"]
	bw := Chart{Context: "system.ip", Family: "ip", Units: "kilobits/s", Title: "IP bandwidth", Type: "area"}
	e.Incremental(bw, "received", x["InOctets"], 8.0/1000)
	e.Incremental(bw, "sent", x["OutOctets"], 8.0/1000)
	mc := Chart{Context: "ip.mcast", Family: "multicast", Units: "kilobits/s", Title: "IP multicast bandwidth"}
	e.Incremental(mc, "received", x["InMcastOctets"], 8.0/1000)
	e.Incremental(mc, "sent", x["OutMcastOctets"], 8.0/1000)
	ecn := Chart{Context: "ip.ecnpkts", Family: "ecn", Units: "packets/s", Title: "IP ECN statistics"}
	e.Incremental(ecn, "CEP", x["InCEPkts"], 1)
	e.Incremental(ecn, "NoECTP", x["InNoECTPkts"], 1)
	e.Incremental(ecn, "ECTP0", x["InECT0Pkts"], 1)
	e.Incremental(ecn, "ECTP1", x["InECT1Pkts"], 1)
	return nil
}

// ---------------------------------------------------------------- sockstat

// Sockstat reads socket counts from /proc/net/sockstat and sockstat6.
type Sockstat struct{ fs fsys }

func (*Sockstat) Info() Info { return Info{Name: "proc.net.sockstat", Family: "sockets"} }

func parseSockstat(lines []string) map[string]map[string]float64 {
	out := map[string]map[string]float64{}
	for _, l := range lines {
		name, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		m := map[string]float64{}
		for i := 0; i+1 < len(f); i += 2 {
			m[f[i]] = pf(f[i+1])
		}
		out[name] = m
	}
	return out
}

func (s *Sockstat) Collect(_ time.Time, e *Emitter) error {
	lines, err := readLines(s.fs.procPath("net", "sockstat"))
	if err != nil {
		return err
	}
	m := parseSockstat(lines)
	e.Gauge(Chart{Context: "ipv4.sockstat_sockets", Family: "sockets", Units: "sockets", Title: "IPv4 sockets used"}, "used", m["sockets"]["used"])
	tc := Chart{Context: "ipv4.sockstat_tcp_sockets", Family: "tcp", Units: "sockets", Title: "IPv4 TCP sockets"}
	for _, k := range []string{"alloc", "orphan", "inuse", "tw"} {
		e.Gauge(tc, k, m["TCP"][k])
	}
	e.Gauge(Chart{Context: "ipv4.sockstat_tcp_mem", Family: "tcp", Units: "KiB", Title: "IPv4 TCP sockets memory"}, "mem", m["TCP"]["mem"]*4)
	e.Gauge(Chart{Context: "ipv4.sockstat_udp_sockets", Family: "udp", Units: "sockets", Title: "IPv4 UDP sockets"}, "inuse", m["UDP"]["inuse"])
	e.Gauge(Chart{Context: "ipv4.sockstat_udp_mem", Family: "udp", Units: "KiB", Title: "IPv4 UDP sockets memory"}, "mem", m["UDP"]["mem"]*4)
	e.Gauge(Chart{Context: "ipv4.sockstat_raw_sockets", Family: "raw", Units: "sockets", Title: "IPv4 RAW sockets"}, "inuse", m["RAW"]["inuse"])
	e.Gauge(Chart{Context: "ipv4.sockstat_frag_sockets", Family: "fragments", Units: "fragments", Title: "IPv4 fragments in use"}, "inuse", m["FRAG"]["inuse"])
	if l6, err := readLines(s.fs.procPath("net", "sockstat6")); err == nil {
		m6 := parseSockstat(l6)
		e.Gauge(Chart{Context: "ipv6.sockstat6_tcp_sockets", Family: "tcp6", Units: "sockets", Title: "IPv6 TCP sockets"}, "inuse", m6["TCP6"]["inuse"])
		e.Gauge(Chart{Context: "ipv6.sockstat6_udp_sockets", Family: "udp6", Units: "sockets", Title: "IPv6 UDP sockets"}, "inuse", m6["UDP6"]["inuse"])
		e.Gauge(Chart{Context: "ipv6.sockstat6_raw_sockets", Family: "raw6", Units: "sockets", Title: "IPv6 RAW sockets"}, "inuse", m6["RAW6"]["inuse"])
	}
	return nil
}

// ---------------------------------------------------------------- conntrack

// Conntrack reads the netfilter connection table size and statistics.
type Conntrack struct{ fs fsys }

func (*Conntrack) Info() Info { return Info{Name: "netfilter.conntrack", Family: "netfilter"} }

func (c *Conntrack) Collect(_ time.Time, e *Emitter) error {
	count, ok := readFloat(c.fs.procPath("sys", "net", "netfilter", "nf_conntrack_count"))
	if !ok {
		return os.ErrNotExist
	}
	e.Gauge(Chart{Context: "netfilter.conntrack_sockets", Family: "connection tracker", Units: "active connections", Title: "Connection tracker connections"}, "connections", count)
	if mx, ok := readFloat(c.fs.procPath("sys", "net", "netfilter", "nf_conntrack_max")); ok && mx > 0 {
		e.Gauge(Chart{Context: "netfilter.conntrack_utilization", Family: "connection tracker", Units: "%", Title: "Connection tracker table utilization"}, "used", count/mx*100)
		e.Gauge(Chart{Context: "netfilter.conntrack_max", Family: "connection tracker", Units: "connections", Title: "Connection tracker table size"}, "max", mx)
	}
	lines, err := readLines(c.fs.procPath("net", "stat", "nf_conntrack"))
	if err != nil || len(lines) < 2 {
		return nil
	}
	hdr := strings.Fields(lines[0])
	sums := make([]float64, len(hdr))
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		for i := range hdr {
			if i < len(f) {
				sums[i] += phex(f[i])
			}
		}
	}
	st := Chart{Context: "netfilter.conntrack_errors", Family: "connection tracker", Units: "events/s", Title: "Connection tracker errors"}
	for i, h := range hdr {
		switch h {
		case "invalid", "insert_failed", "drop", "early_drop", "icmp_error", "search_restart":
			e.Incremental(st, h, sums[i], 1)
		case "found", "new", "insert", "delete":
			e.Incremental(Chart{Context: "netfilter.conntrack_changes", Family: "connection tracker", Units: "events/s", Title: "Connection tracker changes"}, h, sums[i], 1)
		}
	}
	return nil
}

// ---------------------------------------------------------------- softnet

// Softnet reads /proc/net/softnet_stat (hex columns, one row per CPU).
type Softnet struct{ fs fsys }

func (*Softnet) Info() Info { return Info{Name: "proc.net.softnet_stat", Family: "softnet"} }

func (s *Softnet) Collect(_ time.Time, e *Emitter) error {
	lines, err := readLines(s.fs.procPath("net", "softnet_stat"))
	if err != nil {
		return err
	}
	var processed, dropped, squeezed, rps, flowLimit float64
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		processed += phex(f[0])
		dropped += phex(f[1])
		squeezed += phex(f[2])
		if len(f) > 9 {
			rps += phex(f[9])
		}
		if len(f) > 10 {
			flowLimit += phex(f[10])
		}
	}
	ch := Chart{Context: "system.softnet_stat", Family: "softnet", Units: "events/s", Title: "Softnet events"}
	e.Incremental(ch, "processed", processed, 1)
	e.Incremental(ch, "dropped", dropped, 1)
	e.Incremental(ch, "squeezed", squeezed, 1)
	e.Incremental(ch, "received_rps", rps, 1)
	e.Incremental(ch, "flow_limit_count", flowLimit, 1)
	return nil
}
