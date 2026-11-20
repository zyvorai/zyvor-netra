// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// nginxApp reads ngx_http_stub_status_module output.
type nginxApp struct{ cfg AppConfig }

func (n *nginxApp) collect(ctx context.Context, e *Emitter) error {
	b, err := n.cfg.httpGet(ctx, n.cfg.URL)
	if err != nil {
		return err
	}
	st, err := parseNginxStatus(string(b))
	if err != nil {
		return err
	}
	c := n.cfg
	e.Gauge(c.chart("connections", "connections", "connections", "nginx active connections", "line"), "active", st["active"])
	cs := c.chart("connections_status", "connections", "connections", "nginx connections by state", "stacked")
	e.Gauge(cs, "reading", st["reading"])
	e.Gauge(cs, "writing", st["writing"])
	e.Gauge(cs, "idle", st["waiting"])
	ca := c.chart("connections_accepted_handled", "connections", "connections/s", "nginx accepted and handled connections", "line")
	e.Incremental(ca, "accepted", st["accepts"], 1)
	e.Incremental(ca, "handled", st["handled"], 1)
	e.Incremental(c.chart("requests", "requests", "requests/s", "nginx client requests", "line"), "requests", st["requests"], 1)
	return nil
}

func parseNginxStatus(s string) (map[string]float64, error) {
	out := map[string]float64{}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "Active connections:") {
		return nil, errors.New("not an nginx stub_status page")
	}
	out["active"] = pf(strings.TrimSpace(strings.TrimPrefix(lines[0], "Active connections:")))
	f := strings.Fields(lines[2])
	if len(f) < 3 {
		return nil, errors.New("malformed nginx stub_status counters")
	}
	out["accepts"], out["handled"], out["requests"] = pf(f[0]), pf(f[1]), pf(f[2])
	f = strings.Fields(lines[3])
	for i := 0; i+1 < len(f); i += 2 {
		out[strings.ToLower(strings.TrimSuffix(f[i], ":"))] = pf(f[i+1])
	}
	return out, nil
}

// apacheApp reads mod_status machine-readable output (?auto).
type apacheApp struct{ cfg AppConfig }

func (a *apacheApp) collect(ctx context.Context, e *Emitter) error {
	url := a.cfg.URL
	if !strings.Contains(url, "auto") {
		if strings.Contains(url, "?") {
			url += "&auto"
		} else {
			url += "?auto"
		}
	}
	b, err := a.cfg.httpGet(ctx, url)
	if err != nil {
		return err
	}
	st, board := parseApacheStatus(string(b))
	if _, ok := st["BusyWorkers"]; !ok {
		return errors.New("not an Apache mod_status ?auto page")
	}
	c := a.cfg
	if v, ok := st["Total Accesses"]; ok {
		e.Incremental(c.chart("requests", "requests", "requests/s", "Apache requests", "line"), "requests", v, 1)
	}
	if v, ok := st["Total kBytes"]; ok {
		e.Incremental(c.chart("net", "bandwidth", "kilobits/s", "Apache bandwidth", "area"), "sent", v, 8)
	}
	w := c.chart("workers", "workers", "workers", "Apache workers", "stacked")
	e.Gauge(w, "busy", st["BusyWorkers"])
	e.Gauge(w, "idle", st["IdleWorkers"])
	if v, ok := st["ConnsTotal"]; ok {
		e.Gauge(c.chart("connections", "connections", "connections", "Apache connections", "line"), "connections", v)
	}
	if v, ok := st["Uptime"]; ok {
		e.Gauge(c.chart("uptime", "availability", "seconds", "Apache uptime", "line"), "uptime", v)
	}
	if len(board) > 0 {
		sb := c.chart("scoreboard", "workers", "workers", "Apache scoreboard", "stacked")
		for _, k := range []string{"waiting", "starting", "reading", "sending", "keepalive", "dns_lookup", "closing", "logging", "finishing", "idle_cleanup", "open"} {
			e.Gauge(sb, k, board[k])
		}
	}
	return nil
}

func parseApacheStatus(s string) (map[string]float64, map[string]float64) {
	st := map[string]float64{}
	board := map[string]float64{}
	names := map[rune]string{'_': "waiting", 'S': "starting", 'R': "reading", 'W': "sending", 'K': "keepalive", 'D': "dns_lookup", 'C': "closing", 'L': "logging", 'G': "finishing", 'I': "idle_cleanup", '.': "open"}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "Scoreboard" {
			for _, r := range v {
				if n, ok := names[r]; ok {
					board[n]++
				}
			}
			continue
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			st[k] = f
		}
	}
	return st, board
}

// haproxyApp reads the stats CSV (";csv" on the stats URI).
type haproxyApp struct{ cfg AppConfig }

func (h *haproxyApp) collect(ctx context.Context, e *Emitter) error {
	url := h.cfg.URL
	if !strings.Contains(url, "csv") {
		url = strings.TrimRight(url, "/") + "/;csv;norefresh"
	}
	b, err := h.cfg.httpGet(ctx, url)
	if err != nil {
		return err
	}
	rows, err := parseHAProxyCSV(string(b))
	if err != nil {
		return err
	}
	c := h.cfg
	for _, r := range rows {
		sv := r["svname"]
		if sv != "FRONTEND" && sv != "BACKEND" {
			continue
		}
		kind := strings.ToLower(sv)
		px := r["pxname"]
		ch := func(metric, units, title, typ string) Chart {
			x := c.chart(kind+"_"+metric, kind, units, "HAProxy "+kind+" "+title, typ)
			x.ID += "_" + sanitizeID(px)
			x.Labels = copyWithout(x.Labels, "")
			x.Labels["proxy"] = px
			return x
		}
		e.Gauge(ch("sessions", "sessions", "current sessions", "line"), "current", pf(r["scur"]))
		e.Incremental(ch("session_rate", "sessions/s", "new sessions", "line"), "sessions", pf(r["stot"]), 1)
		bw := ch("bandwidth", "kilobits/s", "bandwidth", "area")
		e.Incremental(bw, "in", pf(r["bin"]), 8.0/1000)
		e.Incremental(bw, "out", pf(r["bout"]), 8.0/1000)
		hr := ch("http_responses", "responses/s", "HTTP responses", "stacked")
		for _, k := range []string{"1xx", "2xx", "3xx", "4xx", "5xx", "other"} {
			if v, ok := r["hrsp_"+k]; ok && v != "" {
				e.Incremental(hr, k, pf(v), 1)
			}
		}
		er := ch("errors", "errors/s", "errors", "line")
		for _, k := range []string{"ereq", "econ", "eresp", "dreq", "dresp"} {
			if v, ok := r[k]; ok && v != "" {
				e.Incremental(er, k, pf(v), 1)
			}
		}
		if kind == "backend" {
			up := 0.0
			if strings.HasPrefix(r["status"], "UP") {
				up = 1
			}
			e.Gauge(ch("up", "boolean", "status (1 up)", "line"), "up", up)
			if v := r["act"]; v != "" {
				e.Gauge(ch("servers", "servers", "active servers", "line"), "active", pf(v))
			}
			if v := r["qcur"]; v != "" {
				e.Gauge(ch("queue", "requests", "queued requests", "line"), "queued", pf(v))
			}
		}
	}
	return nil
}

func parseHAProxyCSV(s string) ([]map[string]string, error) {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "# pxname,svname") {
		return nil, errors.New("not an HAProxy stats CSV")
	}
	hdr := strings.Split(strings.TrimPrefix(lines[0], "# "), ",")
	var out []map[string]string
	for _, l := range lines[1:] {
		f := strings.Split(l, ",")
		row := make(map[string]string, len(hdr))
		for i, h := range hdr {
			if i < len(f) && h != "" {
				row[h] = f[i]
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// lineConn sends cmd over TCP and returns the response lines up to and
// including the terminator check.
func lineConn(ctx context.Context, addr string, send []string, done func(line string) bool) ([]string, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	}
	r := bufio.NewReaderSize(conn, 64*1024)
	var lines []string
	for i, cmd := range send {
		if _, err := conn.Write([]byte(cmd)); err != nil {
			return nil, err
		}
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return nil, err
			}
			l = strings.TrimRight(l, "\r\n")
			if i < len(send)-1 {
				// Reply to an earlier command (AUTH): one line.
				if strings.HasPrefix(l, "-") {
					return nil, fmt.Errorf("%s", strings.TrimPrefix(l, "-"))
				}
				break
			}
			lines = append(lines, l)
			if done(l) || len(lines) > 100000 {
				return lines, nil
			}
		}
	}
	return lines, nil
}

func respCommand(args ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.String()
}

// redisApp speaks RESP: optional AUTH, then INFO.
type redisApp struct{ cfg AppConfig }

func (r *redisApp) collect(ctx context.Context, e *Emitter) error {
	var send []string
	if r.cfg.PasswordEnv != "" {
		if pw := os.Getenv(r.cfg.PasswordEnv); pw != "" {
			if u := os.Getenv(r.cfg.UsernameEnv); r.cfg.UsernameEnv != "" && u != "" {
				send = append(send, respCommand("AUTH", u, pw))
			} else {
				send = append(send, respCommand("AUTH", pw))
			}
		}
	}
	send = append(send, respCommand("INFO"))
	var want, got int
	lines, err := lineConn(ctx, r.cfg.Address, send, func(l string) bool {
		if want == 0 {
			if strings.HasPrefix(l, "-") {
				return true
			}
			if strings.HasPrefix(l, "$") {
				want, _ = strconv.Atoi(l[1:])
				return want <= 0
			}
			return false
		}
		got += len(l) + 2
		return got >= want
	})
	if err != nil {
		return err
	}
	if len(lines) > 0 && strings.HasPrefix(lines[0], "-") {
		return fmt.Errorf("redis: %s", strings.TrimPrefix(lines[0], "-"))
	}
	info, keyspace := parseRedisInfo(lines)
	if _, ok := info["connected_clients"]; !ok {
		return errors.New("redis: unexpected INFO reply")
	}
	c := r.cfg
	cl := c.chart("clients", "clients", "clients", "Redis clients", "line")
	e.Gauge(cl, "connected", info["connected_clients"])
	e.Gauge(cl, "blocked", info["blocked_clients"])
	mem := c.chart("memory", "memory", "MiB", "Redis memory", "line")
	e.Gauge(mem, "used", info["used_memory"]/(1<<20))
	e.Gauge(mem, "rss", info["used_memory_rss"]/(1<<20))
	if v, ok := info["maxmemory"]; ok && v > 0 {
		e.Gauge(mem, "max", v/(1<<20))
	}
	if v, ok := info["mem_fragmentation_ratio"]; ok {
		e.Gauge(c.chart("mem_fragmentation_ratio", "memory", "ratio", "Redis memory fragmentation", "line"), "ratio", v)
	}
	e.Incremental(c.chart("commands", "commands", "commands/s", "Redis commands processed", "line"), "processed", info["total_commands_processed"], 1)
	hm := c.chart("keyspace_lookups", "keys", "lookups/s", "Redis keyspace lookups", "stacked")
	e.Incremental(hm, "hits", info["keyspace_hits"], 1)
	e.Incremental(hm, "misses", info["keyspace_misses"], 1)
	ev := c.chart("keys_removed", "keys", "keys/s", "Redis expired and evicted keys", "line")
	e.Incremental(ev, "expired", info["expired_keys"], 1)
	e.Incremental(ev, "evicted", info["evicted_keys"], 1)
	nw := c.chart("net", "network", "kilobits/s", "Redis bandwidth", "area")
	e.Incremental(nw, "received", info["total_net_input_bytes"], 8.0/1000)
	e.Incremental(nw, "sent", info["total_net_output_bytes"], 8.0/1000)
	cn := c.chart("connections", "connections", "connections/s", "Redis connections", "line")
	e.Incremental(cn, "accepted", info["total_connections_received"], 1)
	e.Incremental(cn, "rejected", info["rejected_connections"], 1)
	if v, ok := info["rdb_changes_since_last_save"]; ok {
		e.Gauge(c.chart("rdb_changes", "persistence", "operations", "Redis changes since last save", "line"), "changes", v)
	}
	if v, ok := info["connected_slaves"]; ok {
		e.Gauge(c.chart("replicas", "replication", "replicas", "Redis connected replicas", "line"), "connected", v)
	}
	if v, ok := info["master_link_up"]; ok {
		e.Gauge(c.chart("master_link", "replication", "boolean", "Redis master link (1 up)", "line"), "up", v)
	}
	if len(keyspace) > 0 {
		k := c.chart("keyspace", "keys", "keys", "Redis keys per database", "stacked")
		for db, n := range keyspace {
			e.Gauge(k, db, n)
		}
	}
	return nil
}

func parseRedisInfo(lines []string) (map[string]float64, map[string]float64) {
	info := map[string]float64{}
	keyspace := map[string]float64{}
	for _, l := range lines {
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "$") {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		if strings.HasPrefix(k, "db") && strings.Contains(v, "keys=") {
			for _, kv := range strings.Split(v, ",") {
				if n, ok := strings.CutPrefix(kv, "keys="); ok {
					keyspace[k] = pf(n)
				}
			}
			continue
		}
		if k == "master_link_status" {
			info["master_link_up"] = map[bool]float64{true: 1, false: 0}[v == "up"]
			continue
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			info[k] = f
		}
	}
	return info, keyspace
}

// memcachedApp speaks the text protocol "stats" command.
type memcachedApp struct{ cfg AppConfig }

func (m *memcachedApp) collect(ctx context.Context, e *Emitter) error {
	lines, err := lineConn(ctx, m.cfg.Address, []string{"stats\r\n"}, func(l string) bool { return l == "END" || strings.HasPrefix(l, "ERROR") })
	if err != nil {
		return err
	}
	st := map[string]float64{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 3 && f[0] == "STAT" {
			if v, err := strconv.ParseFloat(f[2], 64); err == nil {
				st[f[1]] = v
			}
		}
	}
	if _, ok := st["curr_connections"]; !ok {
		return errors.New("memcached: unexpected stats reply")
	}
	c := m.cfg
	e.Gauge(c.chart("connections", "connections", "connections", "memcached connections", "line"), "current", st["curr_connections"])
	e.Incremental(c.chart("connections_rate", "connections", "connections/s", "memcached new connections", "line"), "opened", st["total_connections"], 1)
	ops := c.chart("operations", "operations", "operations/s", "memcached operations", "line")
	e.Incremental(ops, "get", st["cmd_get"], 1)
	e.Incremental(ops, "set", st["cmd_set"], 1)
	hm := c.chart("get_hits", "operations", "lookups/s", "memcached get hits and misses", "stacked")
	e.Incremental(hm, "hits", st["get_hits"], 1)
	e.Incremental(hm, "misses", st["get_misses"], 1)
	mem := c.chart("memory", "memory", "MiB", "memcached memory", "line")
	e.Gauge(mem, "used", st["bytes"]/(1<<20))
	e.Gauge(mem, "limit", st["limit_maxbytes"]/(1<<20))
	e.Gauge(c.chart("items", "items", "items", "memcached items", "line"), "current", st["curr_items"])
	e.Incremental(c.chart("evictions", "items", "items/s", "memcached evictions", "line"), "evicted", st["evictions"], 1)
	nw := c.chart("net", "network", "kilobits/s", "memcached bandwidth", "area")
	e.Incremental(nw, "received", st["bytes_read"], 8.0/1000)
	e.Incremental(nw, "sent", st["bytes_written"], 8.0/1000)
	return nil
}
