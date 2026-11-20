// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package lokipush pushes Netra's audit events and block/deny events to Grafana
// Loki over its HTTP push API. It follows the same optional, best-effort,
// leader-only shape as the syslog, Snowflake and OTLP sinks, and shares their
// delivery logic (internal/pushfeed): watermarks that advance only past
// delivered batches, per-node block watermarks, and a permanently rejected
// batch dropped rather than retried forever.
//
// How the data is shaped for Loki: stream labels are a small, bounded set
// (job, class, severity, node, plus a few operator-chosen static labels), and
// the whole event travels in the log line as JSON, queried with `| json`.
// Putting fields such as an IP, a target or an actor in labels is the classic
// way to melt a Loki with cardinality; here they stay in the line.
//
// Delivery is at-least-once, which suits Loki: it drops an entry identical to
// one it already holds, so resending a batch after a partial failure is
// harmless.
package lokipush

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/pushfeed"
	"github.com/zyvorai/netra/internal/siem"
)

// Class selects which events are pushed.
type Class string

const (
	ClassAudit Class = "audit"
	ClassBlock Class = "block"
)

const (
	pushPath = "/loki/api/v1/push"
	// maxBatch bounds events per cycle step; maxBody bounds one HTTP body
	// (uncompressed), well under Loki's default 4 MiB request limit.
	maxBatch = 500
	maxBody  = 1 << 20
	// maxLine bounds one log line; Loki's default is 256 KiB.
	maxLine     = 64 << 10
	gzipMinSize = 1024
	maxExtra    = 8
)

var labelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// reserved label names Netra sets itself.
var reserved = map[string]bool{"job": true, "class": true, "severity": true, "node": true}

// Config configures a Pusher. URL is the Loki base URL (http://loki:3100) or
// the full push URL.
type Config struct {
	URL string
	// TenantID becomes the X-Scope-OrgID header (multi-tenant Loki).
	TenantID string
	// Username/Password send HTTP basic auth (Grafana Cloud, reverse proxies).
	Username string
	Password string
	// Headers are extra request headers, typically a token. Never logged.
	Headers map[string]string
	// Job is the `job` label. Default "netra".
	Job string
	// Labels are extra static stream labels (e.g. cluster=prod).
	Labels  map[string]string
	Timeout time.Duration
	// Classes selects what to push; empty means both.
	Classes []Class
}

// Sources are the feeds a Pusher polls each cycle. Any may be nil.
type Sources struct {
	// Audit returns audit events newest-first, as store.Audit does.
	Audit func() []models.AuditEvent
	// Blocks returns retained block/deny events keyed by node.
	Blocks func() map[string][]models.FastPathEvent
}

// Pusher is safe for one Run at a time.
type Pusher struct {
	cfg     Config
	url     string
	enabled map[Class]bool
	client  *http.Client
	log     *slog.Logger
	feed    *pushfeed.Feed
	now     func() time.Time

	mu      sync.Mutex
	started bool
}

// New validates cfg, so a misconfiguration fails at startup rather than as a
// stream of failed pushes.
func New(cfg Config, log *slog.Logger) (*Pusher, error) {
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil, errors.New("loki url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("loki url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("loki url must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("loki url has no host")
	}
	if u.User != nil {
		return nil, errors.New("loki url must not embed credentials; use NETRA_LOKI_USERNAME/NETRA_LOKI_PASSWORD")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("loki url must not carry a query or fragment")
	}
	base := strings.TrimRight(u.String(), "/")
	if !strings.HasSuffix(base, pushPath) {
		base += pushPath
	}
	for k, v := range cfg.Headers {
		if strings.TrimSpace(k) == "" || strings.ContainsAny(k+v, "\r\n") {
			return nil, errors.New("loki header has an empty name or a newline")
		}
	}
	if strings.ContainsAny(cfg.TenantID+cfg.Username+cfg.Password, "\r\n") {
		return nil, errors.New("loki tenant/username/password must not contain newlines")
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return nil, errors.New("loki basic auth needs both a username and a password")
	}
	if cfg.Job == "" {
		cfg.Job = "netra"
	}
	if err := validateLabel("job", cfg.Job); err != nil {
		return nil, err
	}
	if len(cfg.Labels) > maxExtra {
		return nil, fmt.Errorf("at most %d extra labels are allowed", maxExtra)
	}
	for k, v := range cfg.Labels {
		if !labelNameRE.MatchString(k) || strings.HasPrefix(k, "__") {
			return nil, fmt.Errorf("label name %q is invalid (letters, digits, underscore; not starting __)", k)
		}
		if reserved[k] {
			return nil, fmt.Errorf("label %q is set by Netra and cannot be overridden", k)
		}
		if err := validateLabel(k, v); err != nil {
			return nil, err
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	classes := cfg.Classes
	if len(classes) == 0 {
		classes = []Class{ClassAudit, ClassBlock}
	}
	if log == nil {
		log = slog.Default()
	}
	p := &Pusher{
		cfg: cfg, url: base, enabled: map[Class]bool{}, log: log, now: time.Now,
		feed: pushfeed.New("loki", log),
		client: &http.Client{
			Timeout: cfg.Timeout,
			// A redirected POST becomes a GET and the data is silently dropped;
			// surface the 3xx as a failure instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	for _, c := range classes {
		p.enabled[c] = true
	}
	return p, nil
}

func validateLabel(name, v string) error {
	if v == "" || len(v) > 128 {
		return fmt.Errorf("label %s must be 1-128 characters", name)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("label %s contains a control character", name)
		}
	}
	return nil
}

// ParseClasses reads a comma-separated subset of audit,block.
func ParseClasses(s string) ([]Class, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	seen := map[Class]bool{}
	var out []Class
	for part := range strings.SplitSeq(s, ",") {
		c := Class(strings.ToLower(strings.TrimSpace(part)))
		switch c {
		case "":
		case ClassAudit, ClassBlock:
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		default:
			return nil, fmt.Errorf("unknown loki class %q (want audit, block)", part)
		}
	}
	return out, nil
}

// Run pushes once immediately and then every interval until ctx ends.
func (p *Pusher) Run(ctx context.Context, interval time.Duration, src Sources) {
	if p == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	p.Once(ctx, src)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.Once(ctx, src)
		}
	}
}

// Once runs a single push cycle. Failures are logged, never returned: pull
// export keeps working while Loki is down, and events are retried next cycle
// because the watermark only advances on success.
func (p *Pusher) Once(ctx context.Context, src Sources) {
	if p.enabled[ClassAudit] && src.Audit != nil {
		p.feed.DrainAudit(src.Audit(), maxBatch, func(recs []siem.Record) error { return p.send(ctx, recs) })
	}
	if p.enabled[ClassBlock] && src.Blocks != nil {
		p.feed.DrainBlocks(src.Blocks(), maxBatch, func(_ string, recs []siem.Record) error { return p.send(ctx, recs) })
	}
}

type stream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// send encodes recs (oldest first) and POSTs them, splitting so no single body
// exceeds maxBody. If a later chunk fails the whole batch is retried; the
// chunks that already landed are then duplicates, which Loki discards.
func (p *Pusher) send(ctx context.Context, recs []siem.Record) error {
	type entry struct {
		labels string
		set    map[string]string
		ts     string
		line   string
	}
	entries := make([]entry, 0, len(recs))
	for _, r := range recs {
		set := p.labelsFor(r)
		entries = append(entries, entry{labels: labelKey(set), set: set, ts: p.timestamp(r), line: line(r)})
	}

	for len(entries) > 0 {
		size, n := 0, 0
		for n < len(entries) && (n == 0 || size+len(entries[n].line)+64 <= maxBody) {
			size += len(entries[n].line) + 64
			n++
		}
		byStream := map[string]*stream{}
		var order []string
		for _, e := range entries[:n] {
			st := byStream[e.labels]
			if st == nil {
				st = &stream{Stream: e.set}
				byStream[e.labels] = st
				order = append(order, e.labels)
			}
			st.Values = append(st.Values, [2]string{e.ts, e.line})
		}
		payload := struct {
			Streams []stream `json:"streams"`
		}{}
		for _, k := range order {
			payload.Streams = append(payload.Streams, *byStream[k])
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if err := p.post(ctx, body); err != nil {
			return err
		}
		entries = entries[n:]
	}
	return nil
}

// labelsFor builds the bounded label set for a record.
func (p *Pusher) labelsFor(r siem.Record) map[string]string {
	set := map[string]string{"job": p.cfg.Job, "class": string(classOf(r)), "severity": severityLabel(r.Severity)}
	if r.Node != "" {
		set["node"] = sanitizeLabel(r.Node)
	}
	for k, v := range p.cfg.Labels {
		set[k] = v
	}
	return set
}

func classOf(r siem.Record) Class {
	if r.Class == "block" {
		return ClassBlock
	}
	return ClassAudit
}

// severityLabel keeps severity to a fixed vocabulary so a stray value cannot
// mint new streams.
func severityLabel(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "info", "low", "medium", "warning", "high", "critical":
		return v
	default:
		return "info"
	}
}

func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 63 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func labelKey(set map[string]string) string {
	// Deterministic and collision-free: sorted "k=v" joined by a byte that
	// cannot appear in a label value (control characters are rejected).
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(set[k])
		b.WriteByte(1)
	}
	return b.String()
}

func (p *Pusher) timestamp(r siem.Record) string {
	at := r.At
	if at.IsZero() {
		at = p.now()
	}
	return strconv.FormatInt(at.UTC().UnixNano(), 10)
}

// line renders the whole record as one JSON line. An oversized record loses its
// free-form Details first, then its message, so it is never rejected outright.
func line(r siem.Record) string {
	b, err := json.Marshal(r)
	if err == nil && len(b) <= maxLine {
		return string(b)
	}
	r.Details = nil
	if b, err = json.Marshal(r); err == nil && len(b) <= maxLine {
		return string(b)
	}
	if len(r.Message) > 1024 {
		r.Message = r.Message[:1024] + "…"
	}
	b, _ = json.Marshal(r)
	return string(b)
}

func (p *Pusher) post(ctx context.Context, body []byte) error {
	var reader io.Reader = bytes.NewReader(body)
	gz := len(body) >= gzipMinSize
	if gz {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(body); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		reader = &buf
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if p.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", p.cfg.TenantID)
	}
	if p.cfg.Username != "" {
		req.SetBasicAuth(p.cfg.Username, p.cfg.Password)
	}
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &pushfeed.StatusError{Code: resp.StatusCode, Body: string(b)}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return nil
}
