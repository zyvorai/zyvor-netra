// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package collectors

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// ephemeralMaxLines bounds how many socket lines one file contributes.
	ephemeralMaxLines = 2_000_000
	// ephemeralMaxKeys bounds the distinct (local, remote) pairs tracked.
	ephemeralMaxKeys = 262_144
)

// EphemeralPorts measures how close the host's own outbound sockets are to
// exhausting the ephemeral port range. Exhaustion is per destination: a
// client can hold at most (range size) ports toward one (local address,
// remote address, remote port) triple, so the busiest triple, not the total,
// is the number that matters. It reads /proc/net/{tcp,tcp6,udp,udp6} and
// net.ipv4.ip_local_port_range only, keeps no address in a metric, and
// never writes. Ports held by SNAT in the conntrack table are not visible
// here (see docs/capacity-forecast.md).
type EphemeralPorts struct {
	fs fsys
	// every is overridable by tests.
	every time.Duration
}

func (e *EphemeralPorts) Info() Info {
	d := e.every
	if d == 0 {
		d = 10 * time.Second
	}
	return Info{Name: "proc.net.ephemeral_ports", Family: "tcp", Every: d}
}

// parsePortRange parses the "low high" contents of ip_local_port_range.
func parsePortRange(s string) (lo, hi int, ok bool) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, 0, false
	}
	l, err1 := strconv.Atoi(f[0])
	h, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
		return 0, 0, false
	}
	return l, h, true
}

// socketLine extracts the local port, the (local, remote) key and the state
// from one /proc/net/{tcp,udp} data line. ok is false for a malformed line.
func socketLine(line string) (port int, key string, state string, ok bool) {
	f := strings.Fields(line)
	if len(f) < 4 {
		return 0, "", "", false
	}
	li := strings.LastIndexByte(f[1], ':')
	if li <= 0 || li == len(f[1])-1 || len(f[1])-li-1 > 4 {
		return 0, "", "", false
	}
	p, err := strconv.ParseUint(f[1][li+1:], 16, 16)
	if err != nil || strings.IndexByte(f[2], ':') <= 0 {
		return 0, "", "", false
	}
	return int(p), f[1][:li] + ">" + f[2], f[3], true
}

type ephemeralScan struct {
	inRange   int
	perDest   map[string]int
	truncated bool
}

func (s *ephemeralScan) file(path string, lo, hi int, tcp bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	sc.Scan() // header
	for n := 0; sc.Scan(); n++ {
		if n >= ephemeralMaxLines {
			s.truncated = true
			return
		}
		port, key, st, ok := socketLine(sc.Text())
		if !ok || port < lo || port > hi {
			continue
		}
		if tcp && st == "0A" { // LISTEN: a listener inside the range is not an outbound port
			continue
		}
		s.inRange++
		if _, seen := s.perDest[key]; !seen && len(s.perDest) >= ephemeralMaxKeys {
			s.truncated = true
			continue
		}
		s.perDest[key]++
	}
}

func (e *EphemeralPorts) Collect(_ time.Time, em *Emitter) error {
	raw, err := readTrim(e.fs.procPath("sys", "net", "ipv4", "ip_local_port_range"))
	if err != nil {
		return err
	}
	lo, hi, ok := parsePortRange(raw)
	if !ok {
		return nil // a malformed range is not worth a collector failure
	}
	sc := &ephemeralScan{perDest: map[string]int{}}
	for _, p := range []struct {
		name string
		tcp  bool
	}{{"tcp", true}, {"tcp6", true}, {"udp", false}, {"udp6", false}} {
		sc.file(e.fs.procPath("net", p.name), lo, hi, p.tcp)
	}
	maxPer := 0
	for _, c := range sc.perDest {
		if c > maxPer {
			maxPer = c
		}
	}
	size := float64(hi - lo + 1)
	ch := Chart{Context: "net.ephemeral_ports", Family: "tcp", Units: "ports", Title: "Ephemeral port usage"}
	em.Gauge(ch, "in_use", float64(sc.inRange))
	em.Gauge(ch, "max_per_destination", float64(maxPer))
	em.Gauge(ch, "range_size", size)
	em.Gauge(Chart{Context: "net.ephemeral_utilization", Family: "tcp", Units: "%", Title: "Ephemeral port utilization (busiest destination)"}, "used", float64(maxPer)/size*100)
	trunc := 0.0
	if sc.truncated {
		trunc = 1
	}
	em.Gauge(Chart{Context: "net.ephemeral_truncated", Family: "tcp", Units: "flag", Title: "Ephemeral port scan was truncated"}, "truncated", trunc)
	return nil
}
