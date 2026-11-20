// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package policypack builds review-only CiliumNetworkPolicy manifests that
// allow egress to operator-sanctioned hostname suffixes. Netra never applies
// these; durable enforcement stays with PacketWolf/Cilium after operator review.
package policypack

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/appcat"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/policy"
	"github.com/zyvorai/netra/internal/shadowsaas"
)

// Pack is one review-only CNP suggestion for a workload selector.
type Pack struct {
	ID               string            `json:"id"`
	Namespace        string            `json:"namespace"`
	Name             string            `json:"name"`
	Selector         map[string]string `json:"selector"`
	FQDNs            []string          `json:"fqdns"`
	PodCount         int               `json:"podCount"`
	Manifest         map[string]any    `json:"manifest"`
	Rationale        []string          `json:"rationale"`
	PreferPacketWolf bool              `json:"preferPacketWolf"`
}

// Result is GET /api/v1/insights/policy-packs.
type Result struct {
	GeneratedAt    time.Time `json:"generatedAt"`
	Packs          []Pack    `json:"packs"`
	Count          int       `json:"count"`
	SanctionedList int       `json:"sanctionedListSize"`
	ObservedHosts  int       `json:"observedSanctionedHosts"`
	Capped         bool      `json:"capped"`
	Note           string    `json:"note"`
}

const MaxPacks = 100

// Build groups workloads by namespace+selector and emits toFQDNs CNPs for
// sanctioned hosts that those workloads actually contacted (SNI/Host/DNS).
// sanctioned nil/empty → shadowsaas.DefaultSanctioned().
func Build(agents []models.AgentStatus, sanctioned []string, limit int) Result {
	now := time.Now().UTC()
	if limit <= 0 || limit > MaxPacks {
		limit = MaxPacks
	}
	if len(sanctioned) == 0 {
		sanctioned = shadowsaas.DefaultSanctioned()
	}
	type key struct {
		ns  string
		sel string
	}
	type agg struct {
		ns    string
		sel   map[string]string
		fqdns map[string]struct{}
		pods  map[string]struct{}
	}
	by := map[key]*agg{}
	observedSanctioned := map[string]struct{}{}

	wlLookup := func(agents []models.AgentStatus) map[string]models.WorkloadIdentity {
		out := map[string]models.WorkloadIdentity{}
		for _, a := range agents {
			if a.Stale {
				continue
			}
			for _, w := range a.Workloads {
				if w.CgroupID != 0 {
					out[fmt.Sprintf("cg:%d", w.CgroupID)] = w
				}
				if w.Namespace != "" && w.Pod != "" {
					out[w.Namespace+"/"+w.Pod] = w
				}
			}
		}
		return out
	}
	wls := wlLookup(agents)

	resolve := func(ns, pod, kind, name string, cgroup uint64) (string, string, string, string, map[string]string) {
		w, ok := wls[ns+"/"+pod]
		if !ok && cgroup != 0 {
			w, ok = wls[fmt.Sprintf("cg:%d", cgroup)]
		}
		if ok {
			if ns == "" {
				ns = w.Namespace
			}
			if pod == "" {
				pod = w.Pod
			}
			if kind == "" {
				kind = w.WorkloadKind
			}
			if name == "" {
				name = w.WorkloadName
			}
			return ns, pod, kind, name, w.Labels
		}
		return ns, pod, kind, name, nil
	}

	consider := func(host, ns, pod, kind, name string, labels map[string]string) {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || !strings.Contains(host, ".") {
			return
		}
		if !appcat.MatchHostSuffix(host, sanctioned) {
			return
		}
		observedSanctioned[host] = struct{}{}
		sel := policy.RecommendedSelector(labels, strings.ToLower(kind), pod)
		if len(sel) == 0 {
			return
		}
		if ns == "" {
			ns = "default"
		}
		k := key{ns: ns, sel: selectorKey(sel)}
		g := by[k]
		if g == nil {
			g = &agg{ns: ns, sel: sel, fqdns: map[string]struct{}{}, pods: map[string]struct{}{}}
			by[k] = g
		}
		g.fqdns[host] = struct{}{}
		if pod != "" {
			g.pods[ns+"/"+pod] = struct{}{}
		}
	}

	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, t := range a.TLSMetadata {
			ns, pod, kind, name, labels := resolve(t.Namespace, t.Pod, t.WorkloadKind, t.WorkloadName, t.CgroupID)
			consider(t.SNI, ns, pod, kind, name, labels)
		}
		for _, h := range a.HTTPMetadata {
			ns, pod, kind, name, labels := resolve(h.Namespace, h.Pod, h.WorkloadKind, h.WorkloadName, h.CgroupID)
			consider(h.Host, ns, pod, kind, name, labels)
		}
		for _, d := range a.DNSHealth {
			ns, pod, kind, name, labels := resolve(d.Namespace, d.Pod, d.WorkloadKind, d.WorkloadName, d.CgroupID)
			consider(d.Name, ns, pod, kind, name, labels)
		}
	}

	packs := make([]Pack, 0, len(by))
	for _, g := range by {
		fqdns := make([]string, 0, len(g.fqdns))
		for h := range g.fqdns {
			fqdns = append(fqdns, h)
		}
		sort.Strings(fqdns)
		if len(fqdns) == 0 {
			continue
		}
		if len(fqdns) > 40 {
			fqdns = fqdns[:40]
		}
		name := packName(g.sel)
		id := fmt.Sprintf("%s/%s", g.ns, name)
		toFQDNs := make([]map[string]any, 0, len(fqdns))
		for _, h := range fqdns {
			toFQDNs = append(toFQDNs, map[string]any{"matchName": h})
		}
		manifest := map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata": map[string]any{
				"name":      name,
				"namespace": g.ns,
				"labels": map[string]string{
					"app.kubernetes.io/managed-by": "netra",
					"netra.zyvor.dev/pack":         "sanctioned-egress",
				},
				"annotations": map[string]string{
					"netra.zyvor.dev/review-only": "true",
					"netra.zyvor.dev/note":        "Review then apply via PacketWolf/Cilium — Netra does not auto-apply.",
				},
			},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": g.sel},
				"egress": []map[string]any{
					{
						"toFQDNs": toFQDNs,
						"toPorts": []map[string]any{
							{"ports": []map[string]any{{"port": "443", "protocol": "TCP"}}},
						},
					},
				},
			},
		}
		packs = append(packs, Pack{
			ID: id, Namespace: g.ns, Name: name, Selector: g.sel, FQDNs: fqdns,
			PodCount: len(g.pods), Manifest: manifest, PreferPacketWolf: true,
			Rationale: []string{
				fmt.Sprintf("%d sanctioned host(s) observed from this selector", len(fqdns)),
				"Review-only CNP draft; apply with PacketWolf or kubectl after change-control",
				"Does not deny unsanctioned traffic — pair with shadow-saas board for that",
			},
		})
	}
	sort.Slice(packs, func(i, j int) bool {
		if packs[i].Namespace != packs[j].Namespace {
			return packs[i].Namespace < packs[j].Namespace
		}
		return packs[i].Name < packs[j].Name
	})
	capped := false
	if len(packs) > limit {
		packs = packs[:limit]
		capped = true
	}
	return Result{
		GeneratedAt: now, Packs: packs, Count: len(packs),
		SanctionedList: len(sanctioned), ObservedHosts: len(observedSanctioned),
		Capped: capped,
		Note:   "Review-only sanctioned-egress CiliumNetworkPolicy packs. Netra does not apply them; prefer PacketWolf for durable policy.",
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

func packName(sel map[string]string) string {
	for _, k := range []string{"app.kubernetes.io/name", "app", "app.kubernetes.io/instance"} {
		if v := sel[k]; v != "" {
			return "netra-sanctioned-" + sanitizeDNS(v)
		}
	}
	for _, v := range sel {
		return "netra-sanctioned-" + sanitizeDNS(v)
	}
	return "netra-sanctioned-egress"
}

func sanitizeDNS(s string) string {
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
		out = "workload"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
