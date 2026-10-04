// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// runApps collects twice, one second apart, so incremental dimensions emit.
func runApps(t *testing.T, a *Apps) map[string]float64 {
	t.Helper()
	e := NewEmitter()
	t0 := time.Unix(1_700_000_000, 0)
	e.Begin(t0)
	if err := a.Collect(t0, e); err != nil {
		t.Fatal(err)
	}
	for _, en := range a.entries {
		en.retry = time.Time{}
	}
	e.Begin(t0.Add(time.Second))
	if err := a.Collect(t0.Add(time.Second), e); err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, s := range e.Samples() {
		out[s.Series.Context+"/"+s.Series.Dimension] = s.V
	}
	return out
}

func TestNginxApacheHAProxyPrometheus(t *testing.T) {
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/stub_status", func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1) * 10
		fmt.Fprintf(w, "Active connections: 3 \nserver accepts handled requests\n %d %d %d \nReading: 1 Writing: 2 Waiting: 4 \n", n, n, n*2)
	})
	mux.HandleFunc("/server-status", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "auto" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "Total Accesses: 100\nTotal kBytes: 50\nUptime: 3600\nBusyWorkers: 5\nIdleWorkers: 20\nConnsTotal: 7\nScoreboard: __WWK...\n")
	})
	mux.HandleFunc("/;csv;norefresh", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other\n"+
			"web,FRONTEND,,,4,10,2000,100,1000,2000,0,0,1,,,,,OPEN,,,,,,,,,1,1,0,,,,0,1,0,5,,,,0,90,5,4,1,0\n"+
			"app,BACKEND,2,5,3,8,200,90,900,1900,0,0,,0,0,0,0,UP,2,2,0,,0,10,0,,1,2,0,,90,,1,1,,4,,,,0,85,3,1,1,0\n"+
			"app,srv1,0,0,1,4,,40,400,800,,0,,0,0,0,0,UP,1,1,0,0,0,10,0,,1,2,1,,40,,2,0,,2,L4OK,,0,0,40,0,0,0,0\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		fmt.Fprintf(w, `# HELP coredns_dns_requests_total Requests.
# TYPE coredns_dns_requests_total counter
coredns_dns_requests_total{server="dns://:53",type="A",zone="."} %d
coredns_dns_requests_total{server="dns://:53",type="AAAA",zone="."} 5
# TYPE coredns_cache_entries gauge
coredns_cache_entries{server="dns://:53",type="success"} 42
# TYPE coredns_dns_request_duration_seconds histogram
coredns_dns_request_duration_seconds_bucket{server="dns://:53",le="0.1"} 9
coredns_dns_request_duration_seconds_bucket{server="dns://:53",le="+Inf"} 10
coredns_dns_request_duration_seconds_sum{server="dns://:53"} %d
coredns_dns_request_duration_seconds_count{server="dns://:53"} %d
# TYPE go_goroutines gauge
go_goroutines 30
`, 100*n, n, 10*n)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	static := []AppConfig{
		{Kind: "nginx", Name: "web", URL: srv.URL + "/stub_status"},
		{Kind: "apache", Name: "site", URL: srv.URL + "/server-status"},
		{Kind: "haproxy", Name: "lb", URL: srv.URL},
		{Kind: "coredns", Name: "dns", URL: srv.URL + "/metrics", Labels: map[string]string{"namespace": "kube-system"}},
	}
	for i := range static {
		if err := static[i].normalize(); err != nil {
			t.Fatal(err)
		}
	}
	got := runApps(t, NewApps(Config{}, static, false, time.Second, nil))

	want := map[string]float64{
		"nginx.connections/active":                                    3,
		"nginx.connections_status/idle":                               4,
		"apache.workers/busy":                                         5,
		"apache.scoreboard/sending":                                   2,
		"apache.scoreboard/open":                                      3,
		"haproxy.frontend_sessions/current":                           4,
		"haproxy.backend_up/up":                                       1,
		"haproxy.backend_servers/active":                              2,
		"coredns.coredns_cache_entries/server=dns://:53,type=success": 42,
		"apps.up/nginx/web":                                           1,
		"apps.up/coredns/dns":                                         1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	// Rates from the second scrape.
	if got["nginx.requests/requests"] <= 0 || got["coredns.coredns_dns_requests_total/server=dns://:53,type=A,zone=."] <= 0 {
		t.Errorf("rates missing: %v", got)
	}
	if v := got["coredns.coredns_dns_request_duration_seconds_mean/server=dns://:53"]; v <= 0 || v > 1 {
		t.Errorf("histogram mean %v", v)
	}
	for k := range got {
		if strings.Contains(k, "_bucket") || strings.HasPrefix(k, "coredns.go_goroutines") {
			t.Errorf("unexpected series %s (buckets and non-included metrics must be skipped)", k)
		}
	}
}

func TestAppSeriesCarryNameAndOperatorLabels(t *testing.T) {
	c := AppConfig{Kind: "nginx", Name: "edge proxy", Labels: map[string]string{"team": "net"}}
	ch := c.chart("requests", "requests", "requests/s", "t", "line")
	s := ch.series("requests")
	if s.Chart != "nginx_edge_proxy.requests" || s.Labels["app_name"] != "edge proxy" || s.Labels["team"] != "net" {
		t.Fatalf("%+v", s)
	}
	if s.Key() == (tsdb.Series{Context: "nginx.requests", Chart: "nginx_other.requests", Dimension: "requests"}).Key() {
		t.Fatal("instances must not collide")
	}
}

func fakeTCP(t *testing.T, handle func(*bufio.Reader, net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(bufio.NewReader(c), c)
			}()
		}
	}()
	return ln.Addr().String()
}

// readRESP reads one RESP array command and returns its arguments.
func readRESP(r *bufio.Reader) []string {
	l, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(l, "*") {
		return nil
	}
	var n int
	fmt.Sscanf(l, "*%d", &n)
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		_, _ = r.ReadString('\n')
		a, _ := r.ReadString('\n')
		args = append(args, strings.TrimRight(a, "\r\n"))
	}
	return args
}

func TestRedisAndMemcached(t *testing.T) {
	var cmds atomic.Int64
	redisAddr := fakeTCP(t, func(r *bufio.Reader, c net.Conn) {
		authed := false
		for {
			args := readRESP(r)
			if args == nil {
				return
			}
			switch strings.ToUpper(args[0]) {
			case "AUTH":
				if args[len(args)-1] == "s3cret" {
					authed = true
					fmt.Fprint(c, "+OK\r\n")
				} else {
					fmt.Fprint(c, "-WRONGPASS invalid password\r\n")
				}
			case "INFO":
				if !authed {
					fmt.Fprint(c, "-NOAUTH Authentication required.\r\n")
					continue
				}
				n := cmds.Add(1000)
				body := fmt.Sprintf("# Clients\r\nconnected_clients:7\r\nblocked_clients:1\r\n# Memory\r\nused_memory:%d\r\nused_memory_rss:%d\r\nmem_fragmentation_ratio:1.25\r\n# Stats\r\ntotal_commands_processed:%d\r\nkeyspace_hits:10\r\nkeyspace_misses:2\r\n# Replication\r\nmaster_link_status:up\r\n# Keyspace\r\ndb0:keys=12,expires=3,avg_ttl=0\r\n", 1<<20, 2<<20, n)
				fmt.Fprintf(c, "$%d\r\n%s\r\n", len(body), body)
			}
		}
	})
	memAddr := fakeTCP(t, func(r *bufio.Reader, c net.Conn) {
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimSpace(l) == "stats" {
				fmt.Fprint(c, "STAT pid 1\r\nSTAT curr_connections 9\r\nSTAT total_connections 100\r\nSTAT cmd_get 50\r\nSTAT get_hits 40\r\nSTAT get_misses 10\r\nSTAT bytes 1048576\r\nSTAT limit_maxbytes 67108864\r\nSTAT curr_items 5\r\nSTAT version 1.6.21\r\nEND\r\n")
			}
		}
	})
	t.Setenv("NETRA_TEST_REDIS_PW", "s3cret")
	static := []AppConfig{
		{Kind: "redis", Name: "cache", Address: redisAddr, PasswordEnv: "NETRA_TEST_REDIS_PW"},
		{Kind: "redis", Name: "noauth", Address: redisAddr},
		{Kind: "memcached", Name: "mc", Address: memAddr},
	}
	for i := range static {
		_ = static[i].normalize()
	}
	a := NewApps(Config{}, static, false, time.Second, nil)
	got := runApps(t, a)
	if got["redis.clients/connected"] != 7 || got["redis.memory/rss"] != 2 || got["redis.keyspace/db0"] != 12 || got["redis.master_link/up"] != 1 {
		t.Fatalf("redis %v", got)
	}
	if got["redis.commands/processed"] != 1000 {
		t.Errorf("redis command rate %v", got["redis.commands/processed"])
	}
	if got["memcached.connections/current"] != 9 || got["memcached.memory/limit"] != 64 {
		t.Fatalf("memcached %v", got)
	}
	if got["apps.up/redis/noauth"] != 0 {
		t.Errorf("unauthenticated redis should report down")
	}
	for _, st := range a.Statuses() {
		if st.ID == "redis/noauth" && !strings.Contains(st.LastError, "NOAUTH") {
			t.Errorf("noauth status %+v", st)
		}
	}
}

func TestLoadAppsConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "apps.yaml")
	_ = os.WriteFile(p, []byte(`apps:
  - kind: prometheus
    name: postgres
    url: http://10.0.0.5:9187/metrics
    include: ["pg_up", "pg_stat_database_*"]
  - kind: redis
    address: redis.default.svc:6379
    password_env: REDIS_PASSWORD
`), 0o600)
	cs, err := LoadAppsConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 || cs[1].Name != "redis" || cs[0].MaxSeries != 2000 || cs[0].Timeout != 2*time.Second {
		t.Fatalf("%+v", cs)
	}
	_ = os.WriteFile(p, []byte("apps:\n  - kind: mysql\n    url: x\n"), 0o600)
	if _, err := LoadAppsConfig(p); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if cs, err := LoadAppsConfig(filepath.Join(t.TempDir(), "missing.yaml")); err != nil || cs != nil {
		t.Fatal("missing file should be empty, not an error")
	}
}

func TestParseProcAddr(t *testing.T) {
	ip, port, ok := parseProcAddr("0100007F:1F90")
	if !ok || ip != "127.0.0.1" || port != 8080 {
		t.Fatalf("%s %d", ip, port)
	}
	ip, port, ok = parseProcAddr("00000000000000000000000000000000:18EB")
	if !ok || ip != "::" || port != 6379 {
		t.Fatalf("%s %d", ip, port)
	}
}

func TestDiscoveryMatchesCommAndSockets(t *testing.T) {
	proc := t.TempDir()
	mk := func(pid, comm, ns string, inodes ...string) {
		d := filepath.Join(proc, pid)
		_ = os.MkdirAll(filepath.Join(d, "fd"), 0o755)
		_ = os.MkdirAll(filepath.Join(d, "ns"), 0o755)
		_ = os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.Symlink(ns, filepath.Join(d, "ns", "net"))
		for i, ino := range inodes {
			_ = os.Symlink("socket:["+ino+"]", filepath.Join(d, "fd", fmt.Sprint(i+3)))
		}
	}
	mk("1", "systemd", "net:[4026531840]")
	mk("100", "nginx", "net:[4026531840]", "111")
	mk("200", "redis-server", "net:[4026531840]", "222")
	mk("300", "postgres_export", "net:[4026531840]", "333")
	mk("400", "nginx", "net:[4026532999]", "444") // pod netns: skipped
	mk("500", "bash", "net:[4026531840]", "555")
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 0 10 0\n" +
		"   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0 0 10 0\n" +
		"   2: 00000000:23E3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 333 1 0 0 10 0\n" +
		"   3: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 444 1 0 0 10 0\n" +
		"   4: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0 0 10 0\n" +
		"   5: 0100007F:0051 0100007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 111 1 0 0 10 0\n"
	_ = os.MkdirAll(filepath.Join(proc, "1", "net"), 0o755)
	_ = os.WriteFile(filepath.Join(proc, "1", "net", "tcp"), []byte(tcp), 0o644)

	d := &appDiscovery{fs: fsys{proc: proc}}
	var got []string
	for _, c := range d.scan() {
		got = append(got, c.Kind+" "+c.URL+c.Address)
	}
	want := []string{
		"nginx http://127.0.0.1:80/stub_status",
		"nginx http://127.0.0.1:80/nginx_status",
		"nginx http://127.0.0.1:80/basic_status",
		"prometheus http://127.0.0.1:9187/metrics",
		"redis 127.0.0.1:6379",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("discovered:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
