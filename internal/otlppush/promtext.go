// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package otlppush

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OTLP aggregation temporality: cumulative, the only kind a Prometheus
// exposition can express.
const aggregationCumulative = 2

type label struct{ k, v string }

// family is one OTLP metric under construction. Families are keyed by
// (kind, name), not by name alone: /metrics emits netra_tcp_retransmissions
// both as a gauge and as a histogram, and those must stay two metrics.
type family struct {
	name, help, kind string // kind: gauge | sum | histogram
	points           []point
	hists            map[string]*histPoint
	histOrder        []string
}

type point struct {
	labels []label
	value  float64
}

type histPoint struct {
	labels  []label
	buckets []bucket
	sum     float64
	count   float64
	hasSum  bool
	hasCnt  bool
}

type bucket struct{ le, cum float64 }

// PromToOTLP converts a Prometheus text exposition (0.0.4) into an
// OTLP/JSON ExportMetricsServiceRequest. Counters become monotonic
// cumulative sums starting at start; gauges stay gauges; histograms are
// re-assembled from their _bucket/_sum/_count series. Untyped and summary
// samples are exported as gauges. Non-finite sample values are skipped
// because OTLP/JSON cannot carry them. The second return is the number of
// metrics in the request.
//
// Deriving the push from the same text /metrics serves keeps the two
// exports from drifting: a new metric is pushed the moment it is scrapeable.
func PromToOTLP(text []byte, start, now time.Time, resource map[string]string) (map[string]any, int, error) {
	types := map[string]string{}
	helps := map[string]string{}
	fams := map[string]*family{}
	var order []*family

	get := func(kind, name string) *family {
		key := kind + "\x00" + name
		f := fams[key]
		if f == nil {
			f = &family{name: name, kind: kind, help: helps[name]}
			if kind == "histogram" {
				f.hists = map[string]*histPoint{}
			}
			fams[key] = f
			order = append(order, f)
		}
		return f
	}

	sc := bufio.NewScanner(bytes.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if comment, isComment := strings.CutPrefix(line, "#"); isComment {
			fields := strings.SplitN(strings.TrimSpace(comment), " ", 3)
			if len(fields) >= 2 {
				switch fields[0] {
				case "TYPE":
					if len(fields) == 3 {
						types[fields[1]] = strings.TrimSpace(fields[2])
					}
				case "HELP":
					help := ""
					if len(fields) == 3 {
						help = unescapeHelp(fields[2])
					}
					helps[fields[1]] = help
				}
			}
			continue
		}
		name, labels, value, ok := parseSample(line)
		if !ok {
			continue
		}

		if base, suffix := histogramBase(name); base != "" && types[base] == "histogram" {
			f := get("histogram", base)
			var le float64
			hasLE := false
			rest := make([]label, 0, len(labels))
			for _, l := range labels {
				if suffix == "_bucket" && l.k == "le" {
					v, err := strconv.ParseFloat(l.v, 64)
					if err != nil {
						continue
					}
					le, hasLE = v, true
					continue
				}
				rest = append(rest, l)
			}
			key := labelKey(rest)
			h := f.hists[key]
			if h == nil {
				h = &histPoint{labels: rest}
				f.hists[key] = h
				f.histOrder = append(f.histOrder, key)
			}
			switch suffix {
			case "_bucket":
				if hasLE && !math.IsNaN(value) {
					h.buckets = append(h.buckets, bucket{le: le, cum: value})
				}
			case "_sum":
				if isFinite(value) {
					h.sum, h.hasSum = value, true
				}
			case "_count":
				if isFinite(value) {
					h.count, h.hasCnt = value, true
				}
			}
			continue
		}

		if !isFinite(value) {
			continue
		}
		kind := "gauge"
		if types[name] == "counter" {
			kind = "sum"
		}
		f := get(kind, name)
		f.points = append(f.points, point{labels: labels, value: value})
	}
	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("read metrics exposition: %w", err)
	}

	startNs := strconv.FormatInt(start.UTC().UnixNano(), 10)
	nowNs := strconv.FormatInt(now.UTC().UnixNano(), 10)
	metrics := make([]map[string]any, 0, len(order))
	for _, f := range order {
		m := map[string]any{"name": f.name}
		if f.help != "" {
			m["description"] = f.help
		}
		switch f.kind {
		case "gauge":
			m["gauge"] = map[string]any{"dataPoints": numberPoints(f.points, "", nowNs)}
		case "sum":
			m["sum"] = map[string]any{
				"aggregationTemporality": aggregationCumulative,
				"isMonotonic":            true,
				"dataPoints":             numberPoints(f.points, startNs, nowNs),
			}
		case "histogram":
			pts := make([]map[string]any, 0, len(f.histOrder))
			for _, k := range f.histOrder {
				if dp, ok := histogramPoint(f.hists[k], startNs, nowNs); ok {
					pts = append(pts, dp)
				}
			}
			if len(pts) == 0 {
				continue
			}
			m["histogram"] = map[string]any{"aggregationTemporality": aggregationCumulative, "dataPoints": pts}
		}
		metrics = append(metrics, m)
	}

	return map[string]any{
		"resourceMetrics": []map[string]any{{
			"resource": map[string]any{"attributes": resourceAttrs(resource)},
			"scopeMetrics": []map[string]any{{
				"scope":   map[string]any{"name": "github.com/zyvorai/netra/internal/otlppush"},
				"metrics": metrics,
			}},
		}},
	}, len(metrics), nil
}

func numberPoints(pts []point, startNs, nowNs string) []map[string]any {
	out := make([]map[string]any, 0, len(pts))
	for _, p := range pts {
		dp := map[string]any{"timeUnixNano": nowNs, "asDouble": p.value}
		if startNs != "" {
			dp["startTimeUnixNano"] = startNs
		}
		if len(p.labels) > 0 {
			dp["attributes"] = labelAttrs(p.labels)
		}
		out = append(out, dp)
	}
	return out
}

// histogramPoint rebuilds an OTLP histogram data point from cumulative
// Prometheus buckets. Explicit bounds are the finite le values; per-bucket
// counts are the differences between neighbours. The overflow bucket is
// derived from _count rather than the +Inf sample so the counts always sum
// to the reported count.
func histogramPoint(h *histPoint, startNs, nowNs string) (map[string]any, bool) {
	sort.Slice(h.buckets, func(i, j int) bool { return h.buckets[i].le < h.buckets[j].le })
	var bounds []float64
	var counts []string
	prev := 0.0
	for _, b := range h.buckets {
		if math.IsInf(b.le, 1) {
			continue
		}
		c := b.cum - prev
		if c < 0 {
			c = 0
		}
		prev = math.Max(prev, b.cum)
		bounds = append(bounds, b.le)
		counts = append(counts, strconv.FormatUint(uint64(c), 10))
	}
	if len(bounds) == 0 && !h.hasCnt {
		return nil, false
	}
	total := h.count
	if !h.hasCnt {
		total = prev
	}
	over := total - prev
	if over < 0 {
		over = 0
	}
	counts = append(counts, strconv.FormatUint(uint64(over), 10))
	if bounds == nil {
		bounds = []float64{}
	}
	dp := map[string]any{
		"startTimeUnixNano": startNs,
		"timeUnixNano":      nowNs,
		"count":             strconv.FormatUint(uint64(total), 10),
		"bucketCounts":      counts,
		"explicitBounds":    bounds,
	}
	if h.hasSum {
		dp["sum"] = h.sum
	}
	if len(h.labels) > 0 {
		dp["attributes"] = labelAttrs(h.labels)
	}
	return dp, true
}

func histogramBase(name string) (base, suffix string) {
	for _, s := range []string{"_bucket", "_sum", "_count"} {
		if base, ok := strings.CutSuffix(name, s); ok {
			return base, s
		}
	}
	return "", ""
}

func isFinite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func labelKey(ls []label) string {
	if len(ls) == 0 {
		return ""
	}
	cp := append([]label(nil), ls...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].k < cp[j].k })
	var b strings.Builder
	for _, l := range cp {
		b.WriteString(l.k)
		b.WriteByte(0)
		b.WriteString(l.v)
		b.WriteByte(1)
	}
	return b.String()
}

func labelAttrs(ls []label) []map[string]any {
	out := make([]map[string]any, 0, len(ls))
	for _, l := range ls {
		out = append(out, strAttr(l.k, l.v))
	}
	return out
}

func resourceAttrs(m map[string]string) []map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, strAttr(k, m[k]))
	}
	return out
}

func strAttr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

// parseSample reads `name{k="v",...} value [timestamp]`. Label values may
// contain the escapes \\ \" \n. It reports ok=false for anything it cannot
// read, so one malformed line never sinks the whole export.
func parseSample(line string) (name string, labels []label, value float64, ok bool) {
	i := 0
	for i < len(line) && line[i] != '{' && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	name = line[:i]
	if name == "" {
		return "", nil, 0, false
	}
	if i < len(line) && line[i] == '{' {
		i++
		for {
			for i < len(line) && (line[i] == ' ' || line[i] == ',') {
				i++
			}
			if i >= len(line) {
				return "", nil, 0, false
			}
			if line[i] == '}' {
				i++
				break
			}
			ks := i
			for i < len(line) && line[i] != '=' {
				i++
			}
			if i+1 >= len(line) || line[i+1] != '"' {
				return "", nil, 0, false
			}
			key := strings.TrimSpace(line[ks:i])
			i += 2
			var v strings.Builder
			closed := false
			for i < len(line) {
				c := line[i]
				if c == '\\' && i+1 < len(line) {
					switch line[i+1] {
					case 'n':
						v.WriteByte('\n')
					default:
						v.WriteByte(line[i+1])
					}
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				v.WriteByte(c)
				i++
			}
			if !closed {
				return "", nil, 0, false
			}
			labels = append(labels, label{key, v.String()})
		}
	}
	fields := strings.Fields(line[i:])
	if len(fields) == 0 {
		return "", nil, 0, false
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", nil, 0, false
	}
	return name, labels, f, true
}

func unescapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	return strings.ReplaceAll(s, `\\`, `\`)
}
