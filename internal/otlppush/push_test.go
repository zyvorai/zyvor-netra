// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package otlppush

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

type received struct {
	path   string
	header http.Header
	body   []byte
}

// collector is a fake OTLP/HTTP endpoint. status, when set, decides the
// response per request so tests can fail specific signals or calls.
type collector struct {
	*httptest.Server
	mu     sync.Mutex
	got    []received
	status func(path string, n int) int
	reply  string
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.got = append(c.got, received{path: r.URL.Path, header: r.Header.Clone(), body: b})
		n := len(c.got)
		status, reply := http.StatusOK, c.reply
		if c.status != nil {
			status = c.status(r.URL.Path, n)
		}
		c.mu.Unlock()
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = io.WriteString(w, reply)
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *collector) byPath(path string) []received {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []received
	for _, r := range c.got {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func (c *collector) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func newPusher(t *testing.T, c *collector, mut func(*Config)) *Pusher {
	t.Helper()
	cfg := Config{Endpoint: c.URL, Timeout: 2 * time.Second, InstanceID: "pod-a", Version: "9.9.9"}
	if mut != nil {
		mut(&cfg)
	}
	p, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func auditEvents(base time.Time, n int) []models.AuditEvent {
	// store.Audit returns newest-first.
	out := make([]models.AuditEvent, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, models.AuditEvent{
			At: base.Add(time.Duration(i) * time.Second), Actor: "op", Action: "policy.apply", Target: fmt.Sprintf("p%d", i),
		})
	}
	return out
}

func blockEv(at time.Time, dst string) models.FastPathEvent {
	return models.FastPathEvent{ObservedAt: at, Action: "blocked", DestinationIP: dst, Protocol: "tcp", Reason: "denylist"}
}

func countLogRecords(t *testing.T, body []byte) int {
	t.Helper()
	var d struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []json.RawMessage `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("logs body is not OTLP JSON: %v\n%s", err, body)
	}
	n := 0
	for _, rl := range d.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			n += len(sl.LogRecords)
		}
	}
	return n
}

func countSpans(t *testing.T, body []byte) int {
	t.Helper()
	var d struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []json.RawMessage `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("traces body is not OTLP JSON: %v\n%s", err, body)
	}
	n := 0
	for _, rs := range d.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			n += len(ss.Spans)
		}
	}
	return n
}

var t0 = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func TestOncePostsAllThreeSignals(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, func(cfg *Config) { cfg.Headers = map[string]string{"Authorization": "Bearer tok"} })

	p.Once(context.Background(), Sources{
		Metrics: func() ([]byte, error) { return []byte("# TYPE netra_agents_total gauge\nnetra_agents_total 3\n"), nil },
		Audit:   func() []models.AuditEvent { return auditEvents(t0, 3) },
		Blocks: func() map[string][]models.FastPathEvent {
			return map[string][]models.FastPathEvent{"node-a": {blockEv(t0, "1.2.3.4"), blockEv(t0.Add(time.Second), "5.6.7.8")}}
		},
	})

	m, l, tr := c.byPath("/v1/metrics"), c.byPath("/v1/logs"), c.byPath("/v1/traces")
	if len(m) != 1 || len(l) != 1 || len(tr) != 1 {
		t.Fatalf("posts metrics=%d logs=%d traces=%d, want 1 each", len(m), len(l), len(tr))
	}
	for _, r := range []received{m[0], l[0], tr[0]} {
		if r.header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s content-type = %q", r.path, r.header.Get("Content-Type"))
		}
		if r.header.Get("Authorization") != "Bearer tok" {
			t.Fatalf("%s missing configured header", r.path)
		}
	}
	if !bytes.Contains(m[0].body, []byte("netra_agents_total")) || !bytes.Contains(m[0].body, []byte(`"service.instance.id"`)) {
		t.Fatalf("metrics body missing metric or resource attrs: %s", m[0].body)
	}
	if got := countLogRecords(t, l[0].body); got != 3 {
		t.Fatalf("log records = %d, want 3", got)
	}
	if got := countSpans(t, tr[0].body); got != 2 {
		t.Fatalf("spans = %d, want 2", got)
	}
}

func TestLogsAndSpansAreNotResentButMetricsAre(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, nil)
	src := Sources{
		Metrics: func() ([]byte, error) { return []byte("x 1\n"), nil },
		Audit:   func() []models.AuditEvent { return auditEvents(t0, 3) },
		Blocks: func() map[string][]models.FastPathEvent {
			return map[string][]models.FastPathEvent{"n": {blockEv(t0, "1.1.1.1")}}
		},
	}
	p.Once(context.Background(), src)
	p.Once(context.Background(), src)

	if got := len(c.byPath("/v1/logs")); got != 1 {
		t.Fatalf("logs posted %d times, want 1 (watermark should suppress the repeat)", got)
	}
	if got := len(c.byPath("/v1/traces")); got != 1 {
		t.Fatalf("traces posted %d times, want 1", got)
	}
	if got := len(c.byPath("/v1/metrics")); got != 2 {
		t.Fatalf("metrics posted %d times, want 2 (cumulative snapshot every cycle)", got)
	}
}

// A failed push must not advance the watermark, or those events are lost
// for good. The next cycle has to send the same ones again.
func TestFailedPushRetriesSameEventsNextCycle(t *testing.T) {
	c := newCollector(t)
	c.status = func(path string, _ int) int {
		if path == "/v1/logs" && len(c.got) <= 1 { // first logs attempt only
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	}
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalLogs} })
	src := Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 4) }}

	p.Once(context.Background(), src)
	p.Once(context.Background(), src)

	logs := c.byPath("/v1/logs")
	if len(logs) != 2 {
		t.Fatalf("logs attempts = %d, want 2 (fail then retry)", len(logs))
	}
	if countLogRecords(t, logs[0].body) != 4 || countLogRecords(t, logs[1].body) != 4 {
		t.Fatal("the retry must carry the same 4 events, not fewer")
	}
	p.Once(context.Background(), src)
	if got := len(c.byPath("/v1/logs")); got != 2 {
		t.Fatalf("after a successful retry nothing should be resent, got %d posts", got)
	}
}

func TestBatchingCommitsWhatSucceededAndResumesTheRest(t *testing.T) {
	c := newCollector(t)
	c.status = func(path string, _ int) int {
		if path == "/v1/logs" && len(c.got) == 2 { // second batch fails
			return http.StatusBadGateway
		}
		return http.StatusOK
	}
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalLogs} })
	src := Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 1200) }}

	p.Once(context.Background(), src) // batch 1 (500) ok, batch 2 fails, batch 3 not attempted
	first := c.byPath("/v1/logs")
	if len(first) != 2 || countLogRecords(t, first[0].body) != 500 {
		t.Fatalf("first cycle: %d posts, first has %d records; want 2 posts, 500 records", len(first), countLogRecords(t, first[0].body))
	}

	p.Once(context.Background(), src) // resumes at event 501
	all := c.byPath("/v1/logs")
	if len(all) != 4 {
		t.Fatalf("posts = %d, want 4 (500 ok, 500 fail, then 500+200 on resume)", len(all))
	}
	if got := countLogRecords(t, all[2].body) + countLogRecords(t, all[3].body); got != 700 {
		t.Fatalf("resume sent %d events, want the remaining 700 (no duplicates of the committed 500)", got)
	}
}

// Agents stamp ObservedAt on their own clocks. One global watermark would
// drop a lagging node's new events once a faster node had advanced it.
func TestBlockWatermarkIsPerNode(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalTraces} })

	events := map[string][]models.FastPathEvent{
		"fast": {blockEv(t0.Add(time.Hour), "1.1.1.1")},
		"slow": {blockEv(t0, "2.2.2.2")},
	}
	src := Sources{Blocks: func() map[string][]models.FastPathEvent { return events }}
	p.Once(context.Background(), src)
	if got := c.total(); got != 2 {
		t.Fatalf("first cycle posts = %d, want one per node", got)
	}

	events["slow"] = append(events["slow"], blockEv(t0.Add(time.Minute), "3.3.3.3"))
	p.Once(context.Background(), src)

	tr := c.byPath("/v1/traces")
	if len(tr) != 3 {
		t.Fatalf("posts = %d, want 3: slow node's new event is older than fast's watermark but must still ship", len(tr))
	}
	if countSpans(t, tr[2].body) != 1 {
		t.Fatalf("second cycle should carry exactly the one new event")
	}
}

func TestOnlyBlockedEventsWithTimestampsBecomeSpans(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalTraces} })
	p.Once(context.Background(), Sources{Blocks: func() map[string][]models.FastPathEvent {
		return map[string][]models.FastPathEvent{"n": {
			{ObservedAt: t0, Action: "allowed"},
			{Action: "blocked"}, // no timestamp: cannot be deduplicated
			blockEv(t0, "9.9.9.9"),
		}}
	}})
	tr := c.byPath("/v1/traces")
	if len(tr) != 1 || countSpans(t, tr[0].body) != 1 {
		t.Fatalf("want exactly one span, got %d posts", len(tr))
	}
}

func TestSignalSubsetOnlyPostsSelected(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalMetrics} })
	p.Once(context.Background(), Sources{
		Metrics: func() ([]byte, error) { return []byte("x 1\n"), nil },
		Audit:   func() []models.AuditEvent { return auditEvents(t0, 2) },
		Blocks: func() map[string][]models.FastPathEvent {
			return map[string][]models.FastPathEvent{"n": {blockEv(t0, "1.1.1.1")}}
		},
	})
	if len(c.byPath("/v1/metrics")) != 1 || len(c.byPath("/v1/logs"))+len(c.byPath("/v1/traces")) != 0 {
		t.Fatalf("only metrics should be pushed, got %d requests", c.total())
	}
}

func TestRedirectIsAFailureNotASilentDrop(t *testing.T) {
	target := newCollector(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	p, err := New(Config{Endpoint: redirector.URL}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	err = p.post(context.Background(), SignalMetrics, []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect must surface as an error, got %v", err)
	}
	if target.total() != 0 {
		t.Fatal("the redirect was followed")
	}
}

func TestNon2xxErrorCarriesStatusAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "bad token")
	}))
	defer srv.Close()
	p, _ := New(Config{Endpoint: srv.URL}, nil)
	err := p.post(context.Background(), SignalLogs, []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("err = %v", err)
	}
}

func TestPartialSuccessIsLoggedButNotRetried(t *testing.T) {
	c := newCollector(t)
	c.reply = `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"body too large"}}`
	var buf bytes.Buffer
	p, _ := New(Config{Endpoint: c.URL, Signals: []Signal{SignalLogs}}, slog.New(slog.NewTextHandler(&buf, nil)))
	src := Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 2) }}
	p.Once(context.Background(), src)
	p.Once(context.Background(), src)
	if !strings.Contains(buf.String(), "partially rejected") || !strings.Contains(buf.String(), "body too large") {
		t.Fatalf("partial rejection not surfaced: %q", buf.String())
	}
	if got := len(c.byPath("/v1/logs")); got != 1 {
		t.Fatalf("accepted-but-partial batch was resent (%d posts)", got)
	}
}

func TestHeadersNeverAppearInLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	var buf bytes.Buffer
	p, _ := New(Config{Endpoint: srv.URL, Headers: map[string]string{"Authorization": "Bearer s3cret-token"}},
		slog.New(slog.NewTextHandler(&buf, nil)))
	p.Once(context.Background(), Sources{Metrics: func() ([]byte, error) { return []byte("x 1\n"), nil }})
	if buf.Len() == 0 {
		t.Fatal("expected a failure to be logged")
	}
	if strings.Contains(buf.String(), "s3cret-token") {
		t.Fatalf("auth header leaked into logs: %s", buf.String())
	}
}

func TestMetricsScrapeFailureSkipsThePush(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalMetrics} })
	p.Once(context.Background(), Sources{Metrics: func() ([]byte, error) { return nil, fmt.Errorf("boom") }})
	if c.total() != 0 {
		t.Fatal("no request should be sent when the scrape fails")
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"empty", Config{}, "required"},
		{"scheme", Config{Endpoint: "ftp://h:4318"}, "http or https"},
		{"no host", Config{Endpoint: "http://"}, "no host"},
		{"userinfo", Config{Endpoint: "http://u:p@h:4318"}, "credentials"},
		{"signal path", Config{Endpoint: "http://h:4318/v1/logs"}, "base URL"},
		{"signal path slash", Config{Endpoint: "http://h:4318/v1/metrics/"}, "base URL"},
		{"query", Config{Endpoint: "http://h:4318?x=1"}, "query"},
		{"header newline", Config{Endpoint: "http://h:4318", Headers: map[string]string{"X": "a\nb"}}, "newline"},
		{"header empty name", Config{Endpoint: "http://h:4318", Headers: map[string]string{" ": "a"}}, "empty name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	// A path prefix on the base URL (collector behind a gateway) is fine.
	p, err := New(Config{Endpoint: "https://gw.example.com/otel/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.urls[SignalLogs] != "https://gw.example.com/otel/v1/logs" {
		t.Fatalf("url = %q", p.urls[SignalLogs])
	}
}

func TestParseHeadersAndSignals(t *testing.T) {
	h, err := ParseHeaders(" a=1, b = two=parts ,,")
	if err != nil || h["a"] != "1" || h["b"] != "two=parts" || len(h) != 2 {
		t.Fatalf("headers = %v, err = %v", h, err)
	}
	if h, err := ParseHeaders(""); h != nil || err != nil {
		t.Fatalf("empty headers = %v, %v", h, err)
	}
	for _, bad := range []string{"novalue", "=v"} {
		if _, err := ParseHeaders(bad); err == nil {
			t.Fatalf("ParseHeaders(%q) should fail", bad)
		}
	}

	s, err := ParseSignals("Logs, metrics,logs")
	if err != nil || len(s) != 2 || s[0] != SignalLogs || s[1] != SignalMetrics {
		t.Fatalf("signals = %v, err = %v", s, err)
	}
	if _, err := ParseSignals("metrics,profiles"); err == nil {
		t.Fatal("unknown signal must be rejected")
	}
}

func TestScrapeHandler(t *testing.T) {
	ok := ScrapeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, "x 1\n")
	}), "/metrics", nil)
	b, err := ok()
	if err != nil || string(b) != "x 1\n" {
		t.Fatalf("scrape = %q, %v", b, err)
	}
	bad := ScrapeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}), "/metrics", nil)
	if _, err := bad(); err == nil {
		t.Fatal("non-200 scrape must be an error")
	}
}

func TestRunPushesImmediatelyThenStopsOnCancel(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalMetrics} })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx, 20*time.Millisecond, Sources{Metrics: func() ([]byte, error) { return []byte("x 1\n"), nil }})
		close(done)
	}()
	deadline := time.After(2 * time.Second)
	for len(c.byPath("/v1/metrics")) < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d pushes in 2s at a 20ms interval", len(c.byPath("/v1/metrics")))
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestRunRefusesToStartTwice(t *testing.T) {
	c := newCollector(t)
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalMetrics} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, time.Hour, Sources{Metrics: func() ([]byte, error) { return []byte("x 1\n"), nil }})
	for len(c.byPath("/v1/metrics")) < 1 {
		time.Sleep(2 * time.Millisecond)
	}
	second := make(chan struct{})
	go func() {
		p.Run(ctx, time.Hour, Sources{})
		close(second)
	}()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("a second Run on the same Pusher should return immediately")
	}
}

func TestScrapeHandlerSendsConfiguredHeaders(t *testing.T) {
	var got string
	scrape := ScrapeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "x 1\n")
	}), "/metrics", http.Header{"Authorization": {"Bearer scrape-secret"}})
	if _, err := scrape(); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer scrape-secret" {
		t.Fatalf("Authorization = %q, want the configured bearer", got)
	}
}

// A collector that permanently rejects a batch (HTTP 400) must not wedge the
// exporter behind it: the OTLP spec says a 400 is never retried.
func TestAPermanentlyRejectedLogBatchIsDroppedNotRetriedForever(t *testing.T) {
	c := newCollector(t)
	c.status = func(path string, _ int) int {
		if path == "/v1/logs" && len(c.got) == 1 { // the very first logs request
			return http.StatusBadRequest
		}
		return http.StatusOK
	}
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalLogs} })
	first := auditEvents(t0, 3)
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return first }})
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return first }})
	if got := len(c.byPath("/v1/logs")); got != 1 {
		t.Fatalf("logs posted %d times; the rejected batch was retried instead of dropped", got)
	}
	// Later events still flow.
	later := auditEvents(t0, 5)
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return later }})
	logs := c.byPath("/v1/logs")
	if len(logs) != 2 || countLogRecords(t, logs[1].body) != 2 {
		t.Fatalf("after the drop, only the 2 new events should ship; posts=%d", len(logs))
	}
}

func TestAuthFailuresAreRetriedNotDropped(t *testing.T) {
	c := newCollector(t)
	c.status = func(path string, _ int) int {
		if path == "/v1/logs" && len(c.got) <= 2 {
			return http.StatusUnauthorized // a fixable credentials problem: keep the data
		}
		return http.StatusOK
	}
	p := newPusher(t, c, func(cfg *Config) { cfg.Signals = []Signal{SignalLogs} })
	src := Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 3) }}
	p.Once(context.Background(), src)
	p.Once(context.Background(), src)
	p.Once(context.Background(), src) // credentials fixed: the same 3 events now go through
	logs := c.byPath("/v1/logs")
	if len(logs) != 3 || countLogRecords(t, logs[2].body) != 3 {
		t.Fatalf("posts=%d; the events must survive an outage of credentials and arrive once fixed", len(logs))
	}
}
