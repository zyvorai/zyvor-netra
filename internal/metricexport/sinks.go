// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricexport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// httpPost sends body and treats any non-2xx as an error, keeping a short
// excerpt of the response for the log.
func httpPost(ctx context.Context, c *http.Client, url string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// ParseHeaders reads "K=V,K2=V2" (the OTEL_EXPORTER_OTLP_HEADERS style).
func ParseHeaders(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// RemoteWrite is a Prometheus remote-write 1.0 sink.
type RemoteWrite struct {
	URL     string
	Headers map[string]string // e.g. Authorization; from operator config only
	Prefix  string            // metric name prefix, default "netra"
	Client  *http.Client
}

func (r *RemoteWrite) Name() string { return "prometheus-remote-write" }

// encodeWriteRequest hand-encodes prometheus.WriteRequest:
//
//	WriteRequest { repeated TimeSeries timeseries = 1; }
//	TimeSeries   { repeated Label labels = 1; repeated Sample samples = 2; }
//	Label        { string name = 1; string value = 2; }
//	Sample       { double value = 1; int64 timestamp = 2; } // milliseconds
func encodeWriteRequest(prefix string, batch []Series) []byte {
	var out []byte
	for _, s := range batch {
		var ts []byte
		label := func(k, v string) {
			var l []byte
			l = protowire.AppendTag(l, 1, protowire.BytesType)
			l = protowire.AppendString(l, k)
			l = protowire.AppendTag(l, 2, protowire.BytesType)
			l = protowire.AppendString(l, v)
			ts = protowire.AppendTag(ts, 1, protowire.BytesType)
			ts = protowire.AppendBytes(ts, l)
		}
		ls := append(labelsOf(s), [2]string{"__name__", metricName(prefix, s.Series.Context)})
		sort.Slice(ls, func(i, j int) bool { return ls[i][0] < ls[j][0] })
		for _, kv := range ls {
			label(kv[0], kv[1])
		}
		for _, p := range s.Points {
			var sm []byte
			sm = protowire.AppendTag(sm, 1, protowire.Fixed64Type)
			sm = protowire.AppendFixed64(sm, math.Float64bits(p.V))
			sm = protowire.AppendTag(sm, 2, protowire.VarintType)
			sm = protowire.AppendVarint(sm, uint64(p.T*1000))
			ts = protowire.AppendTag(ts, 2, protowire.BytesType)
			ts = protowire.AppendBytes(ts, sm)
		}
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, ts)
	}
	return out
}

func (r *RemoteWrite) Send(ctx context.Context, batch []Series) error {
	prefix := r.Prefix
	if prefix == "" {
		prefix = "netra"
	}
	hdr := map[string]string{
		"Content-Encoding":                  "snappy",
		"Content-Type":                      "application/x-protobuf",
		"User-Agent":                        "netra-metricexport",
		"X-Prometheus-Remote-Write-Version": "0.1.0",
	}
	for k, v := range r.Headers {
		hdr[k] = v
	}
	c := r.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	// Large batches are split so a single request stays well under typical
	// receiver limits.
	const perReq = 2000
	for i := 0; i < len(batch); i += perReq {
		j := min(len(batch), i+perReq)
		if err := httpPost(ctx, c, r.URL, snappyEncode(encodeWriteRequest(prefix, batch[i:j])), hdr); err != nil {
			return err
		}
	}
	return nil
}

// OTLP is an OTLP/HTTP JSON metrics sink (POST {endpoint}/v1/metrics).
type OTLP struct {
	Endpoint string // base URL; /v1/metrics is appended unless already present
	Headers  map[string]string
	Prefix   string // default "netra"
	Resource map[string]string
	Client   *http.Client
}

func (o *OTLP) Name() string { return "otlp" }

func otlpAttr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

// otlpBody groups series by metric name into gauges.
func otlpBody(prefix string, resource map[string]string, batch []Series) map[string]any {
	byName := map[string]map[string]any{}
	var order []string
	for _, s := range batch {
		name := strings.ReplaceAll(metricName(prefix, s.Series.Context), "_", ".")
		m := byName[name]
		if m == nil {
			m = map[string]any{"name": name, "unit": s.Series.Units, "description": s.Series.Title, "gauge": map[string]any{"dataPoints": []any{}}}
			byName[name] = m
			order = append(order, name)
		}
		attrs := []any{}
		for _, kv := range labelsOf(s) {
			attrs = append(attrs, otlpAttr(kv[0], kv[1]))
		}
		g := m["gauge"].(map[string]any)
		dps := g["dataPoints"].([]any)
		for _, p := range s.Points {
			dps = append(dps, map[string]any{"timeUnixNano": strconv.FormatInt(p.T*1e9, 10), "asDouble": p.V, "attributes": attrs})
		}
		g["dataPoints"] = dps
	}
	metrics := make([]any, 0, len(order))
	for _, n := range order {
		metrics = append(metrics, byName[n])
	}
	res := []any{otlpAttr("service.name", "netra")}
	for k, v := range resource {
		res = append(res, otlpAttr(k, v))
	}
	return map[string]any{"resourceMetrics": []any{map[string]any{
		"resource":     map[string]any{"attributes": res},
		"scopeMetrics": []any{map[string]any{"scope": map[string]any{"name": "netra.metrics"}, "metrics": metrics}},
	}}}
}

func (o *OTLP) Send(ctx context.Context, batch []Series) error {
	prefix := o.Prefix
	if prefix == "" {
		prefix = "netra"
	}
	url := strings.TrimRight(o.Endpoint, "/")
	if !strings.HasSuffix(url, "/v1/metrics") {
		url += "/v1/metrics"
	}
	hdr := map[string]string{"Content-Type": "application/json"}
	for k, v := range o.Headers {
		hdr[k] = v
	}
	c := o.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	const perReq = 1000
	for i := 0; i < len(batch); i += perReq {
		j := min(len(batch), i+perReq)
		body, err := json.Marshal(otlpBody(prefix, o.Resource, batch[i:j]))
		if err != nil {
			return err
		}
		if err := httpPost(ctx, c, url, body, hdr); err != nil {
			return err
		}
	}
	return nil
}

// Graphite is a Graphite plaintext sink over TCP:
// "<prefix>.<node>.<chart>.<dimension> <value> <unix>\n".
type Graphite struct {
	Addr   string // host:port
	Prefix string // default "netra"
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (g *Graphite) Name() string { return "graphite" }

func graphitePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

func graphiteLines(prefix string, batch []Series, w io.Writer) error {
	bw := bufio.NewWriter(w)
	for _, s := range batch {
		path := graphitePart(prefix) + "." + graphitePart(s.Node) + "." + graphitePart(s.Series.Chart) + "." + graphitePart(s.Series.Dimension)
		for _, p := range s.Points {
			if _, err := fmt.Fprintf(bw, "%s %s %d\n", path, strconv.FormatFloat(p.V, 'g', -1, 64), p.T); err != nil {
				return err
			}
		}
	}
	return bw.Flush()
}

func (g *Graphite) Send(ctx context.Context, batch []Series) error {
	prefix := g.Prefix
	if prefix == "" {
		prefix = "netra"
	}
	dial := g.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", g.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return graphiteLines(prefix, batch, conn)
}
