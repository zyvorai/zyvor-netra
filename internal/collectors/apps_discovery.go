// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// appDiscovery finds applications listening in the host network namespace.
// It matches each listening TCP socket to its owning process through
// /proc/<pid>/fd socket inodes and identifies the application from
// /proc/<pid>/comm only; it never reads cmdline or environ. Processes in
// other network namespaces (most pods) are skipped: their loopback is not
// reachable from the agent, so they belong in the static apps config.
type appDiscovery struct{ fs fsys }

type listenSock struct {
	ip   string
	port int
}

// appProbe maps a process comm to the endpoints to try on its ports.
type appProbe struct {
	kind  string
	paths []string // HTTP paths; empty for TCP protocols
	ports []int    // preferred ports; empty means every listening port
}

var appProbes = map[string]appProbe{
	"nginx":        {kind: "nginx", paths: []string{"/stub_status", "/nginx_status", "/basic_status"}},
	"openresty":    {kind: "nginx", paths: []string{"/stub_status", "/nginx_status"}},
	"httpd":        {kind: "apache", paths: []string{"/server-status?auto"}},
	"apache2":      {kind: "apache", paths: []string{"/server-status?auto"}},
	"haproxy":      {kind: "haproxy", paths: []string{"/;csv;norefresh", "/stats;csv;norefresh", "/haproxy?stats;csv;norefresh"}},
	"redis-server": {kind: "redis"},
	"memcached":    {kind: "memcached"},
	"envoy":        {kind: "envoy", paths: []string{"/stats/prometheus"}, ports: []int{9901, 15000, 19000}},
	"coredns":      {kind: "coredns", paths: []string{"/metrics"}, ports: []int{9153}},
	"etcd":         {kind: "etcd", paths: []string{"/metrics"}, ports: []int{2381, 2379}},
}

func (d *appDiscovery) netns(pid string) string {
	l, err := os.Readlink(d.fs.procPath(pid, "ns", "net"))
	if err != nil {
		return ""
	}
	return l
}

// listeners parses /proc/net/tcp{,6} for LISTEN sockets keyed by inode.
func (d *appDiscovery) listeners() map[string]listenSock {
	out := map[string]listenSock{}
	for _, f := range []string{"tcp", "tcp6"} {
		lines, err := readLines(d.fs.procPath("1", "net", f))
		if err != nil {
			continue
		}
		for _, l := range lines[min(1, len(lines)):] {
			fs := strings.Fields(l)
			if len(fs) < 10 || fs[3] != "0A" {
				continue
			}
			ip, port, ok := parseProcAddr(fs[1])
			if !ok {
				continue
			}
			out[fs[9]] = listenSock{ip: ip, port: port}
		}
	}
	return out
}

// parseProcAddr decodes "0100007F:1F90" (little-endian 32-bit words).
func parseProcAddr(s string) (string, int, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0, false
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b).String(), int(port), true
}

// reachable turns a bind address into one the agent can dial.
func reachable(ip string) string {
	switch ip {
	case "0.0.0.0", "::", "":
		return "127.0.0.1"
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

func (d *appDiscovery) scan() []AppConfig {
	hostNS := d.netns("1")
	socks := d.listeners()
	if hostNS == "" || len(socks) == 0 {
		return nil
	}
	entries, err := os.ReadDir(d.fs.proc)
	if err != nil {
		return nil
	}
	var out []AppConfig
	seen := map[string]bool{}
	for _, ent := range entries {
		pid := ent.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		comm, err := readTrim(d.fs.procPath(pid, "comm"))
		if err != nil {
			continue
		}
		probe, ok := appProbes[comm]
		// comm is cut at 15 bytes: postgres_exporter reads as postgres_export.
		isExporter := strings.HasSuffix(comm, "_exporter") || (len(comm) == 15 && strings.Contains(comm, "_export"))
		if !ok && !isExporter {
			continue
		}
		if d.netns(pid) != hostNS {
			continue
		}
		ports := d.pidListeners(pid, socks)
		if len(ports) == 0 {
			continue
		}
		if isExporter && !ok {
			probe = appProbe{kind: "prometheus", paths: []string{"/metrics"}}
		}
		for _, ls := range pickPorts(ports, probe.ports) {
			host := fmt.Sprintf("%s:%d", reachable(ls.ip), ls.port)
			name := fmt.Sprintf("%s_%d", comm, ls.port)
			if probe.kind == "redis" || probe.kind == "memcached" {
				c := AppConfig{Kind: probe.kind, Name: name, Address: host, discovered: true}
				if !seen[c.id()] && c.normalize() == nil {
					seen[c.id()] = true
					out = append(out, c)
				}
				continue
			}
			// One candidate per port; the first path that answers wins on
			// later scans because failing guesses back off for 10 minutes.
			for i, p := range probe.paths {
				n := name
				if i > 0 {
					n = fmt.Sprintf("%s_%d", name, i)
				}
				c := AppConfig{Kind: probe.kind, Name: n, URL: "http://" + host + p, discovered: true}
				if !seen[c.id()] && c.normalize() == nil {
					seen[c.id()] = true
					out = append(out, c)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id() < out[j].id() })
	return out
}

func (d *appDiscovery) pidListeners(pid string, socks map[string]listenSock) []listenSock {
	fds, err := os.ReadDir(d.fs.procPath(pid, "fd"))
	if err != nil {
		return nil
	}
	var out []listenSock
	seen := map[int]bool{}
	for _, fd := range fds {
		l, err := os.Readlink(d.fs.procPath(pid, "fd", fd.Name()))
		if err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		ino := strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")
		if s, ok := socks[ino]; ok && !seen[s.port] {
			seen[s.port] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].port < out[j].port })
	return out
}

func pickPorts(have []listenSock, prefer []int) []listenSock {
	if len(prefer) == 0 {
		if len(have) > 4 {
			return have[:4]
		}
		return have
	}
	var out []listenSock
	for _, p := range prefer {
		for _, h := range have {
			if h.port == p {
				out = append(out, h)
			}
		}
	}
	return out
}
