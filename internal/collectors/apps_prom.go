// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/tsdb"
)

// Default metric sets for the Prometheus-backed presets. Only these are
// collected unless the operator sets include.
var (
	envoyInclude = []string{
		"envoy_server_live", "envoy_server_uptime", "envoy_server_memory_allocated", "envoy_server_total_connections",
		"envoy_cluster_upstream_cx_active", "envoy_cluster_upstream_cx_total", "envoy_cluster_upstream_cx_connect_fail",
		"envoy_cluster_upstream_rq_total", "envoy_cluster_upstream_rq_active", "envoy_cluster_upstream_rq_pending_active",
		"envoy_cluster_upstream_rq_timeout", "envoy_cluster_upstream_rq_retry", "envoy_cluster_upstream_rq_xx",
		"envoy_cluster_membership_healthy", "envoy_cluster_membership_total",
		"envoy_http_downstream_cx_active", "envoy_http_downstream_rq_total", "envoy_http_downstream_rq_xx", "envoy_http_downstream_rq_active",
		"envoy_listener_downstream_cx_active", "envoy_listener_downstream_cx_total",
	}
	corednsInclude = []string{
		"coredns_dns_requests_total", "coredns_dns_responses_total", "coredns_dns_request_duration_seconds",
		"coredns_cache_entries", "coredns_cache_hits_total", "coredns_cache_misses_total",
		"coredns_forward_requests_total", "coredns_forward_responses_total", "coredns_forward_healthcheck_failures_total",
		"coredns_panics_total", "coredns_plugin_enabled",
	}
	etcdInclude = []string{
		"etcd_server_has_leader", "etcd_server_leader_changes_seen_total", "etcd_server_proposals_*",
		"etcd_mvcc_db_total_size_in_bytes", "etcd_mvcc_db_total_size_in_use_in_bytes", "etcd_debugging_mvcc_keys_total",
		"etcd_disk_wal_fsync_duration_seconds", "etcd_disk_backend_commit_duration_seconds",
		"etcd_network_peer_round_trip_time_seconds", "etcd_network_client_grpc_*_bytes_total",
		"grpc_server_handled_total",
	}
)

// promApp scrapes a Prometheus text endpoint. Counters become per-second
// rates, gauges stay absolute, histograms and summaries contribute their
// _sum and _count rates plus a mean (sum/count) gauge; buckets and
// quantiles are skipped to bound cardinality.
type promApp struct {
	cfg   AppConfig
	types map[string]string
}

func newPromApp(c AppConfig) *promApp { return &promApp{cfg: c, types: map[string]string{}} }

type promSample struct {
	name   string
	labels [][2]string
	value  float64
}

// parsePromText parses the text exposition format. It returns samples and
// the declared TYPE of each metric family.
func parsePromText(b []byte) ([]promSample, map[string]string) {
	types := map[string]string{}
	var out []promSample
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[1] == "TYPE" {
				types[f[2]] = f[3]
			}
			continue
		}
		s, ok := parsePromLine(line)
		if ok {
			out = append(out, s)
		}
	}
	return out, types
}

func parsePromLine(line string) (promSample, bool) {
	var s promSample
	i := strings.IndexAny(line, "{ \t")
	if i <= 0 {
		return s, false
	}
	s.name = line[:i]
	rest := line[i:]
	if rest[0] == '{' {
		end := -1
		inQ := false
		for j := 1; j < len(rest); j++ {
			switch rest[j] {
			case '\\':
				j++
			case '"':
				inQ = !inQ
			case '}':
				if !inQ {
					end = j
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return s, false
		}
		s.labels = parsePromLabels(rest[1:end])
		rest = rest[end+1:]
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return s, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return s, false
	}
	s.value = v
	return s, true
}

func parsePromLabels(s string) [][2]string {
	var out [][2]string
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ,")
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || eq+1 >= len(s) || s[eq+1] != '"' {
			break
		}
		k := strings.TrimSpace(s[:eq])
		var v strings.Builder
		j := eq + 2
		for ; j < len(s) && s[j] != '"'; j++ {
			if s[j] == '\\' && j+1 < len(s) {
				j++
				switch s[j] {
				case 'n':
					v.WriteByte('\n')
				default:
					v.WriteByte(s[j])
				}
				continue
			}
			v.WriteByte(s[j])
		}
		out = append(out, [2]string{k, v.String()})
		if j >= len(s) {
			break
		}
		s = s[j+1:]
	}
	sort.Slice(out, func(a, b int) bool { return out[a][0] < out[b][0] })
	return out
}

func (p *promApp) wanted(name string) bool {
	if len(p.cfg.Include) > 0 && !tsdb.MatchAny(p.cfg.Include, name) {
		return false
	}
	for _, x := range p.cfg.Exclude {
		if tsdb.MatchGlob(x, name) {
			return false
		}
	}
	return true
}

// familyName strips histogram/summary suffixes to find the declared family.
func familyName(name string, types map[string]string) (family, suffix string) {
	for _, suf := range []string{"_bucket", "_sum", "_count", "_total", "_created"} {
		if base, ok := strings.CutSuffix(name, suf); ok {
			if _, declared := types[base]; declared {
				return base, suf
			}
		}
	}
	return name, ""
}

func dimName(labels [][2]string) string {
	if len(labels) == 0 {
		return "value"
	}
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		parts = append(parts, l[0]+"="+l[1])
	}
	return strings.Join(parts, ",")
}

func (p *promApp) collect(ctx context.Context, e *Emitter) error {
	b, err := p.cfg.httpGet(ctx, p.cfg.URL)
	if err != nil {
		return err
	}
	samples, types := parsePromText(b)
	if len(samples) == 0 {
		return fmt.Errorf("%s: no metrics in response", p.cfg.URL)
	}
	type hist struct {
		labels     [][2]string
		sum, count float64
		has        int
	}
	hists := map[string]*hist{}
	n := 0
	for _, s := range samples {
		fam, suf := familyName(s.name, types)
		if !p.wanted(fam) && !p.wanted(s.name) {
			continue
		}
		if n >= p.cfg.MaxSeries {
			break
		}
		typ := types[fam]
		if math.IsNaN(s.value) {
			continue
		}
		switch typ {
		case "histogram", "summary":
			if suf == "_bucket" || (suf == "" && hasLabel(s.labels, "quantile")) || suf == "_created" {
				continue
			}
			key := fam + "|" + dimName(s.labels)
			h := hists[key]
			if h == nil {
				h = &hist{labels: s.labels}
				hists[key] = h
			}
			switch suf {
			case "_sum":
				h.sum, h.has = s.value, h.has|1
				e.Incremental(p.cfg.chart(fam+"_sum", "apps", "units/s", fam+" sum rate", "line"), dimName(s.labels), s.value, 1)
			case "_count":
				h.count, h.has = s.value, h.has|2
				e.Incremental(p.cfg.chart(fam+"_count", "apps", "events/s", fam+" event rate", "line"), dimName(s.labels), s.value, 1)
			}
		case "counter":
			e.Incremental(p.cfg.chart(s.name, "apps", "events/s", s.name, "line"), dimName(s.labels), s.value, 1)
		default:
			e.Gauge(p.cfg.chart(s.name, "apps", "value", s.name, "line"), dimName(s.labels), s.value)
		}
		n++
	}
	for key, h := range hists {
		if h.has == 3 && h.count > 0 {
			fam := key[:strings.IndexByte(key, '|')]
			e.Gauge(p.cfg.chart(fam+"_mean", "apps", "value", fam+" lifetime mean", "line"), dimName(h.labels), h.sum/h.count)
		}
	}
	return nil
}

func hasLabel(ls [][2]string, k string) bool {
	for _, l := range ls {
		if l[0] == k {
			return true
		}
	}
	return false
}
