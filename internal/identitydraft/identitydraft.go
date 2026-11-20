// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package identitydraft joins ServiceAccount + label identity with observed
// egress to produce review-only Zero Trust / CNP drafts. Never auto-applied.
package identitydraft

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/insights"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
)

// Result is GET /api/v1/insights/identity-drafts.
type Result struct {
	GeneratedAt time.Time                 `json:"generatedAt"`
	Drafts      []insights.ZeroTrustDraft `json:"drafts"`
	Count       int                       `json:"count"`
	Identities  int                       `json:"identities"`
	Capped      bool                      `json:"capped"`
	Note        string                    `json:"note"`
}

const MaxDrafts = 100

// Build groups workloads by namespace + ServiceAccount (falling back to label
// selector) and suggests review-only allow_sni drafts for observed hosts,
// plus a Cilium SA-keyed CNP sketch in Draft["ciliumManifest"].
func Build(agents []models.AgentStatus, limit int) Result {
	now := time.Now().UTC()
	if limit <= 0 || limit > MaxDrafts {
		limit = MaxDrafts
	}
	type idKey struct {
		ns, sa string
		sel    string
	}
	type agg struct {
		ns, sa, kind, name string
		sel                map[string]string
		sni                map[string]uint64
		pods               map[string]struct{}
	}
	by := map[idKey]*agg{}
	identities := 0

	for _, a := range agents {
		if a.Stale {
			continue
		}
		wlByCG := map[uint64]models.WorkloadIdentity{}
		wlByPod := map[string]models.WorkloadIdentity{}
		for _, w := range a.Workloads {
			if w.CgroupID != 0 {
				wlByCG[w.CgroupID] = w
			}
			if w.Namespace != "" && w.Pod != "" {
				wlByPod[w.Namespace+"/"+w.Pod] = w
			}
			sel := policy.RecommendedSelector(w.Labels, strings.ToLower(w.WorkloadKind), w.Pod)
			sa := strings.TrimSpace(w.ServiceAccountName)
			if sa == "" {
				sa = "default"
			}
			if w.Namespace == "" || len(sel) == 0 {
				continue
			}
			k := idKey{ns: w.Namespace, sa: sa, sel: selectorKey(sel)}
			if _, ok := by[k]; !ok {
				by[k] = &agg{
					ns: w.Namespace, sa: sa, kind: w.WorkloadKind, name: w.WorkloadName,
					sel: sel, sni: map[string]uint64{}, pods: map[string]struct{}{},
				}
				identities++
			}
			by[k].pods[w.Namespace+"/"+w.Pod] = struct{}{}
		}
		addSNI := func(host, ns, pod string, cgroup uint64, n uint64) {
			host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
			if host == "" || !strings.Contains(host, ".") {
				return
			}
			w, ok := wlByPod[ns+"/"+pod]
			if !ok && cgroup != 0 {
				w, ok = wlByCG[cgroup]
			}
			if !ok {
				return
			}
			sel := policy.RecommendedSelector(w.Labels, strings.ToLower(w.WorkloadKind), w.Pod)
			if len(sel) == 0 {
				return
			}
			sa := strings.TrimSpace(w.ServiceAccountName)
			if sa == "" {
				sa = "default"
			}
			if w.Namespace == "" {
				return
			}
			k := idKey{ns: w.Namespace, sa: sa, sel: selectorKey(sel)}
			g := by[k]
			if g == nil {
				g = &agg{
					ns: w.Namespace, sa: sa, kind: w.WorkloadKind, name: w.WorkloadName,
					sel: sel, sni: map[string]uint64{}, pods: map[string]struct{}{},
				}
				by[k] = g
				identities++
			}
			g.sni[host] += n
			if w.Pod != "" {
				g.pods[w.Namespace+"/"+w.Pod] = struct{}{}
			}
		}
		for _, t := range a.TLSMetadata {
			addSNI(t.SNI, t.Namespace, t.Pod, t.CgroupID, t.Handshakes)
		}
		for _, h := range a.HTTPMetadata {
			addSNI(h.Host, h.Namespace, h.Pod, h.CgroupID, h.Requests)
		}
		for _, d := range a.DNSHealth {
			addSNI(d.Name, d.Namespace, d.Pod, d.CgroupID, d.Queries)
		}
	}

	var drafts []insights.ZeroTrustDraft
	for _, g := range by {
		if len(g.sni) == 0 {
			continue
		}
		hosts := make([]string, 0, len(g.sni))
		var pkts uint64
		for h, n := range g.sni {
			hosts = append(hosts, h)
			pkts += n
		}
		sort.Strings(hosts)
		if len(hosts) > 20 {
			hosts = hosts[:20]
		}
		sum := sha256.Sum256([]byte(g.ns + "|" + g.sa + "|" + selectorKey(g.sel) + "|" + strings.Join(hosts, ",")))
		id := "id-" + hex.EncodeToString(sum[:8])
		ciliumSel := map[string]string{}
		for k, v := range g.sel {
			ciliumSel[k] = v
		}
		// Cilium also labels endpoints with the ServiceAccount name.
		ciliumSel["io.cilium.k8s.policy.serviceaccount"] = g.sa

		toFQDNs := make([]map[string]any, 0, len(hosts))
		for _, h := range hosts {
			toFQDNs = append(toFQDNs, map[string]any{"matchName": h})
		}
		manifest := map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata": map[string]any{
				"name":      "netra-id-" + sanitize(g.sa),
				"namespace": g.ns,
				"labels": map[string]string{
					"app.kubernetes.io/managed-by": "netra",
					"netra.zyvor.dev/pack":         "identity-egress",
				},
				"annotations": map[string]string{
					"netra.zyvor.dev/review-only":     "true",
					"netra.zyvor.dev/service-account": g.sa,
				},
			},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": ciliumSel},
				"egress": []map[string]any{{
					"toFQDNs": toFQDNs,
					"toPorts": []map[string]any{{"ports": []map[string]any{{"port": "443", "protocol": "TCP"}}}},
				}},
			},
		}
		drafts = append(drafts, insights.ZeroTrustDraft{
			ID: id, Namespace: g.ns, WorkloadKind: g.kind, WorkloadName: g.name,
			Selector: g.sel, Kind: "allow_sni",
			Title: fmt.Sprintf("SA %s/%s → %d observed host(s)", g.ns, g.sa, len(hosts)),
			Rationale: []string{
				fmt.Sprintf("ServiceAccount %q with selector %v", g.sa, g.sel),
				fmt.Sprintf("%d pod(s) observed; hosts: %s", len(g.pods), strings.Join(hosts, ", ")),
				"Review-only — apply via PacketWolf/Cilium or use Netra leased allow_sni for incidents",
			},
			Draft: map[string]any{
				"operation":        "review",
				"serviceAccount":   g.sa,
				"hosts":            hosts,
				"ciliumManifest":   manifest,
				"preferPacketWolf": true,
				"netraLeaseHint":   "allow_sni",
			},
			Severity: "info", Packets: pkts,
		})
	}
	sort.Slice(drafts, func(i, j int) bool {
		if drafts[i].Namespace != drafts[j].Namespace {
			return drafts[i].Namespace < drafts[j].Namespace
		}
		return drafts[i].Title < drafts[j].Title
	})
	capped := false
	if len(drafts) > limit {
		drafts = drafts[:limit]
		capped = true
	}
	return Result{
		GeneratedAt: now, Drafts: drafts, Count: len(drafts), Identities: identities,
		Capped: capped,
		Note:   "Review-only identity drafts keyed by ServiceAccount + labels. Netra does not apply; prefer PacketWolf for durable CNP.",
	}
}

func selectorKey(sel map[string]string) string {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+sel[k])
	}
	return strings.Join(parts, ",")
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "sa"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
