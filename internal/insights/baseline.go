// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package insights

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

const BaselineSchemaVersion = 1

// sourceKey is a thin local alias for models.CanonicalSource, kept so this
// package's many call sites don't need a models. prefix at every call.
func sourceKey(ns, pod, kind, workload string, cgroup uint64) string {
	return models.CanonicalSource(ns, pod, kind, workload, cgroup)
}

func CaptureBaseline(agents []models.AgentStatus, now time.Time) models.BehaviorBaseline {
	type k struct{ source, kind, value string }
	counts := map[k]uint64{}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, st := range a.Stats {
			if st.Direction == "ingress" {
				continue
			}
			src := sourceKey(st.Namespace, st.Pod, st.WorkloadKind, st.WorkloadName, st.CgroupID)
			v := st.DestinationIP
			if st.Port != 0 {
				v += ":" + strconv.Itoa(int(st.Port)) + "/" + strings.ToUpper(st.Protocol)
			}
			counts[k{src, "destination", v}] += st.Packets
		}
		for _, d := range a.DNSHealth {
			src := sourceKey(d.Namespace, d.Pod, d.WorkloadKind, d.WorkloadName, d.CgroupID)
			counts[k{src, "dns", strings.ToLower(strings.TrimSuffix(d.Name, "."))}] += d.Queries
		}
		for _, t := range a.TLSMetadata {
			src := sourceKey(t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName, t.CgroupID)
			counts[k{src, "sni", strings.ToLower(t.SNI)}] += t.Handshakes
		}
		for _, h := range a.HTTPMetadata {
			src := sourceKey(h.Namespace, h.Pod, h.WorkloadKind, h.WorkloadName, h.CgroupID)
			counts[k{src, "http-host", strings.ToLower(h.Host)}] += h.Requests
		}
		for _, c := range a.ConnectionAttempts {
			src := sourceKey(c.Namespace, c.Pod, c.WorkloadKind, c.WorkloadName, c.CgroupID)
			counts[k{src, "remote-port", fmt.Sprintf("%s/%d", strings.ToUpper(c.Protocol), c.RemotePort)}] += c.Attempts
		}
	}
	entries := make([]models.BehaviorBaselineEntry, 0, len(counts))
	for key, n := range counts {
		if key.value == "" {
			continue
		}
		entries = append(entries, models.BehaviorBaselineEntry{Source: key.source, Kind: key.kind, Value: key.value, Count: n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Value < entries[j].Value
	})
	return models.BehaviorBaseline{SchemaVersion: BaselineSchemaVersion, CapturedAt: now.UTC(), Entries: entries}
}

func Drift(b models.BehaviorBaseline, agents []models.AgentStatus) models.DriftResponse {
	if b.SchemaVersion == 0 || b.CapturedAt.IsZero() {
		return models.DriftResponse{}
	}
	current := CaptureBaseline(agents, time.Now())
	known := make(map[string]struct{}, len(b.Entries))
	for _, e := range b.Entries {
		known[e.Source+"\x00"+e.Kind+"\x00"+e.Value] = struct{}{}
	}
	min := map[string]uint64{"destination": 3, "dns": 2, "sni": 2, "http-host": 2, "remote-port": 3}
	findings := make([]models.DriftFinding, 0)
	for _, e := range current.Entries {
		if _, ok := known[e.Source+"\x00"+e.Kind+"\x00"+e.Value]; ok {
			continue
		}
		if e.Count < min[e.Kind] {
			continue
		}
		severity := "info"
		if e.Kind == "destination" || e.Kind == "sni" {
			severity = "warning"
		}
		findings = append(findings, models.DriftFinding{
			Severity: severity, Kind: e.Kind, Source: e.Source, Value: e.Value, Count: e.Count,
			Message: fmt.Sprintf("new %s observed after baseline capture", e.Kind),
		})
	}
	rank := map[string]int{"warning": 2, "info": 1}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Severity] != rank[findings[j].Severity] {
			return rank[findings[i].Severity] > rank[findings[j].Severity]
		}
		if findings[i].Count != findings[j].Count {
			return findings[i].Count > findings[j].Count
		}
		if findings[i].Source != findings[j].Source {
			return findings[i].Source < findings[j].Source
		}
		return findings[i].Value < findings[j].Value
	})
	captured := b.CapturedAt
	return models.DriftResponse{BaselineCapturedAt: &captured, Findings: findings}
}
