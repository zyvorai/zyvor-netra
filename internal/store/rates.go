// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const rateBaselineSchemaVersion = 1

type rateTotals struct {
	packets, bytes, blocked     uint64
	connections                 uint64
	dnsQueries, dnsFailures     uint64
	tlsHandshakes, httpRequests uint64
}

type rateSample struct {
	at     time.Time
	totals map[string]rateTotals
}

// rateSource is a thin local alias for models.CanonicalSource, kept so this
// file's call sites don't need a models. prefix at every call.
func rateSource(ns, pod, kind, workload string, cgroup uint64) string {
	return models.CanonicalSource(ns, pod, kind, workload, cgroup)
}

func sampleReport(r models.AgentReport) rateSample {
	at := r.ObservedAt.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	out := rateSample{at: at, totals: map[string]rateTotals{}}
	add := func(source string, fn func(*rateTotals)) {
		x := out.totals[source]
		fn(&x)
		out.totals[source] = x
	}
	for _, st := range r.Stats {
		s := rateSource(st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.CgroupID)
		if s == "node" {
			s = "node:" + r.Node
		}
		add(s, func(x *rateTotals) { x.packets += st.Packets; x.bytes += st.Bytes; x.blocked += st.Blocked })
	}
	for _, st := range r.ConnectionAttempts {
		s := rateSource(st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.CgroupID)
		if s == "node" {
			s = "node:" + r.Node
		}
		add(s, func(x *rateTotals) { x.connections += st.Attempts; x.blocked += st.Blocked })
	}
	for _, st := range r.DNSHealth {
		s := rateSource(st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.CgroupID)
		if s == "node" {
			s = "node:" + r.Node
		}
		add(s, func(x *rateTotals) { x.dnsQueries += st.Queries; x.dnsFailures += st.Failures })
	}
	for _, st := range r.TLSMetadata {
		s := rateSource(st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.CgroupID)
		if s == "node" {
			s = "node:" + r.Node
		}
		add(s, func(x *rateTotals) { x.tlsHandshakes += st.Handshakes; x.blocked += st.Blocked })
	}
	for _, st := range r.HTTPMetadata {
		s := rateSource(st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.CgroupID)
		if s == "node" {
			s = "node:" + r.Node
		}
		add(s, func(x *rateTotals) { x.httpRequests += st.Requests })
	}
	return out
}

func deltaU64(a, b uint64) (uint64, bool) {
	if b < a {
		return 0, false
	}
	return b - a, true
}

func (s *Store) appendRateSampleLocked(r models.AgentReport) {
	if s.rateSamples == nil {
		s.rateSamples = map[string][]rateSample{}
	}
	sample := sampleReport(r)
	items := append(s.rateSamples[r.Node], sample)
	cutoff := sample.at.Add(-2 * time.Hour)
	first := 0
	for first < len(items) && items[first].at.Before(cutoff) {
		first++
	}
	if first > 0 {
		items = append([]rateSample(nil), items[first:]...)
	}
	if len(items) > 240 {
		items = append([]rateSample(nil), items[len(items)-240:]...)
	}
	s.rateSamples[r.Node] = items
}

func (s *Store) RateWindow(window time.Duration, now time.Time) models.RateWindow {
	if window < 30*time.Second {
		window = 30 * time.Second
	}
	if window > 2*time.Hour {
		window = 2 * time.Hour
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	type accum struct {
		metric    models.RateMetric
		intervals int
	}
	all := map[string]*accum{}
	usable := 0
	for _, samples := range s.rateSamples {
		if len(samples) < 2 {
			continue
		}
		end := samples[len(samples)-1]
		startIdx := 0
		threshold := end.at.Add(-window)
		for i := len(samples) - 2; i >= 0; i-- {
			startIdx = i
			if !samples[i].at.After(threshold) {
				break
			}
		}
		start := samples[startIdx]
		seconds := end.at.Sub(start.at).Seconds()
		if seconds <= 0 {
			continue
		}
		usable++
		keys := map[string]bool{}
		for k := range start.totals {
			keys[k] = true
		}
		for k := range end.totals {
			keys[k] = true
		}
		for source := range keys {
			a, b := start.totals[source], end.totals[source]
			dp, ok1 := deltaU64(a.packets, b.packets)
			db, ok2 := deltaU64(a.bytes, b.bytes)
			dbl, ok3 := deltaU64(a.blocked, b.blocked)
			dc, ok4 := deltaU64(a.connections, b.connections)
			dq, ok5 := deltaU64(a.dnsQueries, b.dnsQueries)
			df, ok6 := deltaU64(a.dnsFailures, b.dnsFailures)
			dt, ok7 := deltaU64(a.tlsHandshakes, b.tlsHandshakes)
			dh, ok8 := deltaU64(a.httpRequests, b.httpRequests)
			if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8) {
				continue
			} // counter reset: skip interval
			x := all[source]
			if x == nil {
				x = &accum{metric: models.RateMetric{Source: source}}
				all[source] = x
			}
			x.metric.PacketsPerSecond += float64(dp) / seconds
			x.metric.BytesPerSecond += float64(db) / seconds
			x.metric.BlockedPerSecond += float64(dbl) / seconds
			x.metric.ConnectionsPerSecond += float64(dc) / seconds
			x.metric.DNSQueriesPerSecond += float64(dq) / seconds
			x.metric.DNSFailuresPerSecond += float64(df) / seconds
			x.metric.TLSHandshakesPerSecond += float64(dt) / seconds
			x.metric.HTTPRequestsPerSecond += float64(dh) / seconds
			x.metric.WindowSeconds = seconds
			x.intervals++
		}
	}
	out := models.RateWindow{GeneratedAt: now.UTC(), RequestedWindowSeconds: int64(window.Seconds()), Warming: usable == 0}
	for _, x := range all {
		x.metric.Samples = x.intervals
		out.Metrics = append(out.Metrics, x.metric)
	}
	sort.Slice(out.Metrics, func(i, j int) bool { return out.Metrics[i].BytesPerSecond > out.Metrics[j].BytesPerSecond })
	return out
}

func (s *Store) RateBaseline() models.RateBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRateBaseline(s.rateBaseline)
}

func (s *Store) CaptureRateBaseline(window time.Duration, actor string) (models.RateBaseline, error) {
	current := s.RateWindow(window, time.Now())
	if current.Warming {
		return models.RateBaseline{}, fmt.Errorf("rate window is warming up; at least two fresh agent reports are required")
	}
	b := models.RateBaseline{SchemaVersion: rateBaselineSchemaVersion, CapturedAt: time.Now().UTC(), WindowSeconds: current.RequestedWindowSeconds}
	for _, m := range current.Metrics {
		for metric, rate := range map[string]float64{"packets": m.PacketsPerSecond, "bytes": m.BytesPerSecond, "blocked": m.BlockedPerSecond, "connections": m.ConnectionsPerSecond, "dns-queries": m.DNSQueriesPerSecond, "dns-failures": m.DNSFailuresPerSecond, "tls-handshakes": m.TLSHandshakesPerSecond, "http-requests": m.HTTPRequestsPerSecond} {
			if rate > 0 {
				b.Entries = append(b.Entries, models.RateBaselineEntry{Source: m.Source, Metric: metric, Rate: rate})
			}
		}
	}
	sort.Slice(b.Entries, func(i, j int) bool {
		if b.Entries[i].Source == b.Entries[j].Source {
			return b.Entries[i].Metric < b.Entries[j].Metric
		}
		return b.Entries[i].Source < b.Entries[j].Source
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneRateBaseline(s.rateBaseline), len(s.audit)
	s.rateBaseline = cloneRateBaseline(b)
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "insights.rate-baseline.capture", Target: "traffic-rate", Details: map[string]any{"entries": len(b.Entries), "windowSeconds": b.WindowSeconds}})
	if err := s.persistLocked(); err != nil {
		s.rateBaseline = before
		s.audit = s.audit[:auditLen]
		return models.RateBaseline{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return cloneRateBaseline(b), nil
}

func (s *Store) ClearRateBaseline(actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, auditLen := cloneRateBaseline(s.rateBaseline), len(s.audit)
	s.rateBaseline = models.RateBaseline{}
	s.appendAuditLocked(models.AuditEvent{At: time.Now().UTC(), Actor: actor, Action: "insights.rate-baseline.clear", Target: "traffic-rate"})
	if err := s.persistLocked(); err != nil {
		s.rateBaseline = before
		s.audit = s.audit[:auditLen]
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return nil
}

func cloneRateBaseline(in models.RateBaseline) models.RateBaseline {
	out := in
	out.Entries = append([]models.RateBaselineEntry(nil), in.Entries...)
	return out
}
