// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package lokipush

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var t0 = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

type push struct {
	path    string
	header  http.Header
	user    string
	pass    string
	gzipped bool
	streams []stream
	raw     []byte
}

// fakeLoki decodes real Loki push payloads. status decides each response.
type fakeLoki struct {
	*httptest.Server
	mu     sync.Mutex
	got    []push
	status func(n int) int
}

func newLoki(t *testing.T) *fakeLoki {
	t.Helper()
	f := &fakeLoki{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		p := push{path: r.URL.Path, header: r.Header.Clone(), raw: raw}
		p.user, p.pass, _ = r.BasicAuth()
		body := raw
		if r.Header.Get("Content-Encoding") == "gzip" {
			p.gzipped = true
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				http.Error(w, "bad gzip", 400)
				return
			}
			body, _ = io.ReadAll(zr)
		}
		var payload struct {
			Streams []stream `json:"streams"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "bad json: "+err.Error(), 400)
			return
		}
		p.streams = payload.Streams
		f.mu.Lock()
		f.got = append(f.got, p)
		n := len(f.got)
		code := http.StatusNoContent
		if f.status != nil {
			code = f.status(n)
		}
		f.mu.Unlock()
		w.WriteHeader(code)
		if code >= 400 {
			_, _ = io.WriteString(w, "rejected")
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeLoki) pushes() []push {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]push(nil), f.got...)
}

func (f *fakeLoki) entries() int {
	n := 0
	for _, p := range f.pushes() {
		for _, s := range p.streams {
			n += len(s.Values)
		}
	}
	return n
}

func newPusher(t *testing.T, f *fakeLoki, mut func(*Config)) *Pusher {
	t.Helper()
	cfg := Config{URL: f.URL, Timeout: 2 * time.Second}
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
	out := make([]models.AuditEvent, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, models.AuditEvent{
			At: base.Add(time.Duration(i) * time.Second), Actor: "op", Action: "policy.apply",
			Target: fmt.Sprintf("p%d", i), Details: map[string]any{"risk": "low"},
		})
	}
	return out
}

func blockEv(at time.Time, dst string) models.FastPathEvent {
	return models.FastPathEvent{ObservedAt: at, Action: "blocked", DestinationIP: dst, Protocol: "tcp", Reason: "denylist"}
}

func TestPushShapeMatchesLokisAPI(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 3) }})

	got := f.pushes()
	if len(got) != 1 || got[0].path != "/loki/api/v1/push" {
		t.Fatalf("pushes = %d (path %q), want one to /loki/api/v1/push", len(got), got[0].path)
	}
	if got[0].header.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", got[0].header.Get("Content-Type"))
	}
	if len(got[0].streams) != 1 {
		t.Fatalf("streams = %d, want 1 (one label set)", len(got[0].streams))
	}
	s := got[0].streams[0]
	if s.Stream["job"] != "netra" || s.Stream["class"] != "audit" || s.Stream["severity"] == "" {
		t.Fatalf("labels = %v", s.Stream)
	}
	if len(s.Values) != 3 {
		t.Fatalf("values = %d, want 3", len(s.Values))
	}
	// Timestamps are nanosecond-epoch strings, ascending within the stream.
	prev := int64(0)
	for i, v := range s.Values {
		ns, err := strconv.ParseInt(v[0], 10, 64)
		if err != nil {
			t.Fatalf("timestamp %q is not a nanosecond epoch: %v", v[0], err)
		}
		if ns <= prev {
			t.Fatalf("entry %d timestamp %d not after %d: entries must be oldest first", i, ns, prev)
		}
		prev = ns
	}
	if s.Values[0][0] != strconv.FormatInt(t0.UnixNano(), 10) {
		t.Fatalf("first timestamp = %s, want %d", s.Values[0][0], t0.UnixNano())
	}
	// The whole event is in the line as JSON, so `| json` works.
	var rec map[string]any
	if err := json.Unmarshal([]byte(s.Values[0][1]), &rec); err != nil {
		t.Fatalf("line is not JSON: %v: %q", err, s.Values[0][1])
	}
	if rec["actor"] != "op" || rec["action"] != "policy.apply" || rec["target"] != "p0" {
		t.Fatalf("event fields missing from the line: %v", rec)
	}
}

// Labels are a bounded set; anything high-cardinality stays in the line.
func TestHighCardinalityFieldsNeverBecomeLabels(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	p.Once(context.Background(), Sources{
		Audit: func() []models.AuditEvent { return auditEvents(t0, 50) },
		Blocks: func() map[string][]models.FastPathEvent {
			var evs []models.FastPathEvent
			for i := range 50 {
				evs = append(evs, blockEv(t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("10.0.%d.%d", i/250, i%250)))
			}
			return map[string][]models.FastPathEvent{"node-a": evs}
		},
	})
	allowed := map[string]bool{"job": true, "class": true, "severity": true, "node": true}
	streams := 0
	for _, pu := range f.pushes() {
		for _, s := range pu.streams {
			streams++
			for k := range s.Stream {
				if !allowed[k] {
					t.Fatalf("unexpected label %q: %v", k, s.Stream)
				}
			}
		}
	}
	// 100 distinct events, 50 distinct targets/IPs: still just two streams.
	if streams != 2 {
		t.Fatalf("streams = %d for 100 events, want 2 (audit, and block on node-a)", streams)
	}
}

func TestSeverityAndNodeGroupStreamsAndSeverityIsBounded(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	p.Once(context.Background(), Sources{Blocks: func() map[string][]models.FastPathEvent {
		return map[string][]models.FastPathEvent{
			"node-a": {blockEv(t0, "1.1.1.1")},
			"node-b": {blockEv(t0, "2.2.2.2")},
		}
	}})
	seen := map[string]bool{}
	for _, pu := range f.pushes() {
		for _, s := range pu.streams {
			seen[s.Stream["node"]+"/"+s.Stream["class"]] = true
			if s.Stream["severity"] != "warning" {
				t.Fatalf("block events are warning severity, got %q", s.Stream["severity"])
			}
		}
	}
	if !seen["node-a/block"] || !seen["node-b/block"] || len(seen) != 2 {
		t.Fatalf("streams = %v, want one per node", seen)
	}
	for in, want := range map[string]string{"CRITICAL": "critical", " high ": "high", "": "info", "wat": "info", "warning": "warning"} {
		if got := severityLabel(in); got != want {
			t.Errorf("severityLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStaticLabelsTenantAndAuthAreApplied(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, func(c *Config) {
		c.TenantID = "tenant-7"
		c.Username, c.Password = "grafana", "s3cret"
		c.Headers = map[string]string{"X-Extra": "1"}
		c.Labels = map[string]string{"cluster": "prod", "env": "live"}
		c.Job = "netra-prod"
	})
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 1) }})
	pu := f.pushes()[0]
	if pu.header.Get("X-Scope-OrgID") != "tenant-7" || pu.user != "grafana" || pu.pass != "s3cret" || pu.header.Get("X-Extra") != "1" {
		t.Fatalf("headers/auth wrong: tenant=%q user=%q extra=%q", pu.header.Get("X-Scope-OrgID"), pu.user, pu.header.Get("X-Extra"))
	}
	l := pu.streams[0].Stream
	if l["cluster"] != "prod" || l["env"] != "live" || l["job"] != "netra-prod" {
		t.Fatalf("labels = %v", l)
	}
}

func TestEventsAreNotResentAfterSuccess(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	src := Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 4) }}
	p.Once(context.Background(), src)
	p.Once(context.Background(), src)
	if got := f.entries(); got != 4 {
		t.Fatalf("entries delivered = %d, want 4 (no repeats)", got)
	}
}

func TestTransientFailuresAreRetriedWithTheSameEvents(t *testing.T) {
	for name, code := range map[string]int{"rate limited": 429, "server error": 503, "bad gateway": 502, "auth failure": 401, "wrong url": 404} {
		t.Run(name, func(t *testing.T) {
			f := newLoki(t)
			f.status = func(n int) int {
				if n == 1 {
					return code
				}
				return http.StatusNoContent
			}
			p := newPusher(t, f, nil)
			src := Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 3) }}
			p.Once(context.Background(), src)
			p.Once(context.Background(), src)
			p.Once(context.Background(), src)
			if f.entries() != 6 || len(f.pushes()) != 2 {
				t.Fatalf("pushes=%d entries=%d: want the failed batch resent once, then nothing more", len(f.pushes()), f.entries())
			}
		})
	}
}

// Loki answers 400 for entries it will never take ("entry too far behind",
// "line too long"). Retrying the same batch would wedge the sink.
func TestAPermanentlyRejectedBatchIsDroppedAndLaterEventsStillFlow(t *testing.T) {
	f := newLoki(t)
	f.status = func(n int) int {
		if n == 1 {
			return http.StatusBadRequest
		}
		return http.StatusNoContent
	}
	p := newPusher(t, f, nil)
	first := auditEvents(t0, 3)
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return first }})
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return first }})
	if len(f.pushes()) != 1 {
		t.Fatalf("pushes = %d: the rejected batch was retried instead of dropped", len(f.pushes()))
	}
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 5) }})
	if len(f.pushes()) != 2 || f.pushes()[1].streams[0].Values[0][1] == "" {
		t.Fatalf("later events did not flow after the drop")
	}
	if n := len(f.pushes()[1].streams[0].Values); n != 2 {
		t.Fatalf("second push carried %d entries, want just the 2 new ones", n)
	}
}

func TestPerNodeBlockWatermark(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, func(c *Config) { c.Classes = []Class{ClassBlock} })
	events := map[string][]models.FastPathEvent{"fast": {blockEv(t0.Add(time.Hour), "1.1.1.1")}, "slow": {blockEv(t0, "2.2.2.2")}}
	src := Sources{Blocks: func() map[string][]models.FastPathEvent { return events }}
	p.Once(context.Background(), src)
	events["slow"] = append(events["slow"], blockEv(t0.Add(time.Minute), "3.3.3.3"))
	p.Once(context.Background(), src)
	if got := f.entries(); got != 3 {
		t.Fatalf("entries = %d, want 3: the slow node's new event is older than the fast node's watermark but must ship", got)
	}
}

func TestClassesSelectWhatIsPushed(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, func(c *Config) { c.Classes = []Class{ClassAudit} })
	p.Once(context.Background(), Sources{
		Audit: func() []models.AuditEvent { return auditEvents(t0, 2) },
		Blocks: func() map[string][]models.FastPathEvent {
			return map[string][]models.FastPathEvent{"n": {blockEv(t0, "1.1.1.1")}}
		},
	})
	for _, pu := range f.pushes() {
		for _, s := range pu.streams {
			if s.Stream["class"] != "audit" {
				t.Fatalf("a %q stream was pushed with only audit enabled", s.Stream["class"])
			}
		}
	}
}

func TestLargeBatchesAreGzippedAndSplitBySize(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	// 450 events with ~8KiB details each ≈ 3.6MB of lines: must split under maxBody.
	big := strings.Repeat("x", 8<<10)
	events := make([]models.AuditEvent, 0, 450)
	for i := 449; i >= 0; i-- {
		events = append(events, models.AuditEvent{At: t0.Add(time.Duration(i) * time.Second), Actor: "op", Action: "a", Target: fmt.Sprintf("t%d", i), Details: map[string]any{"blob": big}})
	}
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return events }})
	if f.entries() != 450 {
		t.Fatalf("entries = %d, want 450", f.entries())
	}
	if len(f.pushes()) < 3 {
		t.Fatalf("pushes = %d, want the ~3.6MB batch split into several requests", len(f.pushes()))
	}
	for i, pu := range f.pushes() {
		if !pu.gzipped {
			t.Errorf("push %d was not gzipped", i)
		}
		if len(pu.raw) > maxBody {
			t.Errorf("push %d compressed body is %d bytes", i, len(pu.raw))
		}
	}
	// Order is preserved across the split.
	var targets []string
	for _, pu := range f.pushes() {
		for _, s := range pu.streams {
			for _, v := range s.Values {
				var r struct{ Target string }
				_ = json.Unmarshal([]byte(v[1]), &r)
				targets = append(targets, r.Target)
			}
		}
	}
	if targets[0] != "t0" || targets[449] != "t449" {
		t.Fatalf("order lost across the split: first %s last %s", targets[0], targets[449])
	}
	if !sort.SliceIsSorted(targets, func(i, j int) bool {
		a, _ := strconv.Atoi(targets[i][1:])
		b, _ := strconv.Atoi(targets[j][1:])
		return a < b
	}) {
		t.Fatal("entries are not in ascending order")
	}
}

func TestSmallBodiesAreNotCompressed(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 1) }})
	if f.pushes()[0].gzipped {
		t.Fatal("a tiny body should be sent as plain JSON")
	}
}

func TestAnOversizedLineLosesItsDetailsInsteadOfBeingRejected(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	huge := models.AuditEvent{At: t0, Actor: "op", Action: "a", Target: "t", Details: map[string]any{"blob": strings.Repeat("y", 300<<10)}}
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return []models.AuditEvent{huge} }})
	if f.entries() != 1 {
		t.Fatalf("entries = %d, want the event delivered", f.entries())
	}
	l := f.pushes()[0].streams[0].Values[0][1]
	if len(l) > maxLine || !strings.Contains(l, `"target":"t"`) {
		t.Fatalf("line is %d bytes (max %d) or lost its core fields: %.120s", len(l), maxLine, l)
	}
}

func TestRedirectIsAFailureNotASilentDrop(t *testing.T) {
	target := newLoki(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	p, err := New(Config{URL: redirector.URL}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 2) }})
	if len(target.pushes()) != 0 {
		t.Fatal("the redirect was followed")
	}
}

func TestSecretsNeverAppearInLogs(t *testing.T) {
	f := newLoki(t)
	f.status = func(int) int { return http.StatusForbidden }
	var buf bytes.Buffer
	p, _ := New(Config{URL: f.URL, Username: "u", Password: "hunter2-password", Headers: map[string]string{"Authorization": "Bearer s3cret-token"}},
		slog.New(slog.NewTextHandler(&buf, nil)))
	p.Once(context.Background(), Sources{Audit: func() []models.AuditEvent { return auditEvents(t0, 1) }})
	if buf.Len() == 0 {
		t.Fatal("expected the failure to be logged")
	}
	for _, secret := range []string{"hunter2-password", "s3cret-token"} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("secret %q leaked into logs: %s", secret, buf.String())
		}
	}
}

func TestNewValidation(t *testing.T) {
	cases := map[string]struct {
		cfg  Config
		want string
	}{
		"empty":                 {Config{}, "required"},
		"scheme":                {Config{URL: "ftp://h:3100"}, "http or https"},
		"no host":               {Config{URL: "http://"}, "no host"},
		"userinfo":              {Config{URL: "http://u:p@h:3100"}, "credentials"},
		"query":                 {Config{URL: "http://h:3100?x=1"}, "query"},
		"header newline":        {Config{URL: "http://h:3100", Headers: map[string]string{"X": "a\nb"}}, "newline"},
		"tenant newline":        {Config{URL: "http://h:3100", TenantID: "a\nb"}, "newline"},
		"user without password": {Config{URL: "http://h:3100", Username: "u"}, "both"},
		"bad label name":        {Config{URL: "http://h:3100", Labels: map[string]string{"bad-name": "v"}}, "invalid"},
		"reserved prefix":       {Config{URL: "http://h:3100", Labels: map[string]string{"__x": "v"}}, "invalid"},
		"overriding class":      {Config{URL: "http://h:3100", Labels: map[string]string{"class": "v"}}, "cannot be overridden"},
		"overriding severity":   {Config{URL: "http://h:3100", Labels: map[string]string{"severity": "v"}}, "cannot be overridden"},
		"empty label value":     {Config{URL: "http://h:3100", Labels: map[string]string{"a": ""}}, "1-128"},
		"control char in label": {Config{URL: "http://h:3100", Labels: map[string]string{"a": "x\x01y"}}, "control"},
		"too many labels":       {Config{URL: "http://h:3100", Labels: manyLabels(maxExtra + 1)}, "at most"},
		"bad job":               {Config{URL: "http://h:3100", Job: "a\x00b"}, "control"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tc.cfg, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	for in, want := range map[string]string{
		"http://loki:3100":                  "http://loki:3100/loki/api/v1/push",
		"http://loki:3100/":                 "http://loki:3100/loki/api/v1/push",
		"https://gw.example.com/loki/":      "https://gw.example.com/loki/loki/api/v1/push",
		"http://loki:3100/loki/api/v1/push": "http://loki:3100/loki/api/v1/push",
	} {
		p, err := New(Config{URL: in}, nil)
		if err != nil || p.url != want {
			t.Errorf("New(%q).url = %v, err %v; want %q", in, p, err, want)
		}
	}
}

func manyLabels(n int) map[string]string {
	m := map[string]string{}
	for i := range n {
		m[fmt.Sprintf("l%d", i)] = "v"
	}
	return m
}

func TestParseClasses(t *testing.T) {
	c, err := ParseClasses(" Block ,audit,block")
	if err != nil || len(c) != 2 || c[0] != ClassBlock || c[1] != ClassAudit {
		t.Fatalf("classes = %v, err = %v", c, err)
	}
	if c, err := ParseClasses(""); c != nil || err != nil {
		t.Fatalf("empty = %v, %v", c, err)
	}
	if _, err := ParseClasses("audit,flows"); err == nil {
		t.Fatal("unknown class must be rejected")
	}
}

func TestRunPushesImmediatelyThenStopsAndRefusesASecondRun(t *testing.T) {
	f := newLoki(t)
	p := newPusher(t, f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	n := 0
	src := Sources{Audit: func() []models.AuditEvent {
		mu.Lock()
		defer mu.Unlock()
		n++
		return auditEvents(t0, n) // grows by one each cycle
	}}
	done := make(chan struct{})
	go func() { p.Run(ctx, 20*time.Millisecond, src); close(done) }()
	deadline := time.After(2 * time.Second)
	for f.entries() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d entries in 2s", f.entries())
		case <-time.After(5 * time.Millisecond):
		}
	}
	second := make(chan struct{})
	go func() { p.Run(ctx, time.Hour, Sources{}); close(second) }()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("a second Run on the same Pusher should return immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
