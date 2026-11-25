// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package netpolcoverage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/flowlog"
)

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func pods(t *testing.T, items ...string) []Pod {
	t.Helper()
	out, err := ParsePods(raw(items))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func policies(t *testing.T, items ...string) []Policy {
	t.Helper()
	out, err := ParsePolicies(raw(items))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func raw(items []string) []json.RawMessage {
	var out []json.RawMessage
	for _, s := range items {
		out = append(out, json.RawMessage(s))
	}
	return out
}

func pod(ns, name, app string) string {
	return `{"metadata":{"namespace":"` + ns + `","name":"` + name + `","labels":{"app":"` + app + `"},"ownerReferences":[{"kind":"ReplicaSet","name":"` + app + `-rs","controller":true}]},"spec":{}}`
}

func policy(ns, name, spec string) string {
	return `{"metadata":{"namespace":"` + ns + `","name":"` + name + `"},"spec":` + spec + `}`
}

func find(t *testing.T, r Report, name string) Workload {
	t.Helper()
	for _, w := range r.Workloads {
		if w.Name == name {
			return w
		}
	}
	t.Fatalf("no workload %s in %+v", name, r.Workloads)
	return Workload{}
}

func flow(ns, pod, wl, peer, dir string, bytes uint64) flowlog.Record {
	return flowlog.Record{ObservedAt: now.Add(-time.Minute), Namespace: ns, Pod: pod, WorkloadName: wl, Peer: peer, Direction: dir, Bytes: bytes}
}

func TestIsolationFollowsPolicyTypes(t *testing.T) {
	ps := pods(t, pod("shop", "web-1", "web"), pod("shop", "db-1", "db"), pod("shop", "job-1", "job"))
	pol := policies(t,
		// No policyTypes and no egress rules: ingress only.
		policy("shop", "web-in", `{"podSelector":{"matchLabels":{"app":"web"}},"ingress":[{"from":[{"podSelector":{}}]}]}`),
		// No policyTypes but egress rules: both.
		policy("shop", "db-both", `{"podSelector":{"matchLabels":{"app":"db"}},"egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8"}}]}]}`),
		// A policy in another namespace never applies here.
		policy("other", "deny-all", `{"podSelector":{},"policyTypes":["Ingress","Egress"]}`),
	)
	r := Build(ps, pol, nil, Options{Now: now, All: true})
	web := find(t, r, "web-rs")
	if web.Status != Partial || web.Ingress.Restricted != 1 || web.Egress.Open != 1 || strings.Join(web.Policies, ",") != "web-in" {
		t.Fatalf("%+v", web)
	}
	db := find(t, r, "db-rs")
	if db.Status != Covered || db.Ingress.Restricted != 1 || db.Egress.Restricted != 1 || db.Egress.AnyAddress != 0 {
		t.Fatalf("%+v", db)
	}
	job := find(t, r, "job-rs")
	if job.Status != Uncovered || job.Ingress.Open != 1 || job.Egress.Open != 1 || len(job.Policies) != 0 {
		t.Fatalf("%+v", job)
	}
	if r.Summary.Workloads != 3 || r.Summary.Uncovered != 1 || r.Summary.Partial != 1 || r.Summary.Covered != 1 || r.Summary.EgressUnrestricted != 2 || r.Summary.IngressUnrestricted != 1 {
		t.Fatalf("%+v", r.Summary)
	}
	if len(r.NoPolicyNS) != 0 {
		t.Fatalf("%+v", r.NoPolicyNS)
	}
	// Covered rows are hidden unless asked for.
	if r := Build(ps, pol, nil, Options{Now: now}); r.Total != 2 || r.Summary.Covered != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestEgressOnlyPolicyTypesLeavesIngressOpen(t *testing.T) {
	r := Build(pods(t, pod("a", "p", "x")), policies(t,
		policy("a", "eg", `{"podSelector":{},"policyTypes":["Egress"],"ingress":[{}]}`)), nil, Options{Now: now})
	w := find(t, r, "x-rs")
	if w.Ingress.Open != 1 || w.Egress.Restricted != 1 {
		t.Fatalf("%+v", w)
	}
}

func TestDefaultDenyAllowAllAndAnyAddress(t *testing.T) {
	ps := pods(t, pod("a", "p1", "deny"), pod("a", "p2", "open"), pod("a", "p3", "cidr"), pod("a", "p4", "ports"))
	pol := policies(t,
		policy("a", "deny", `{"podSelector":{"matchLabels":{"app":"deny"}},"policyTypes":["Ingress","Egress"]}`),
		policy("a", "open", `{"podSelector":{"matchLabels":{"app":"open"}},"policyTypes":["Ingress","Egress"],"ingress":[{}],"egress":[{}]}`),
		// Rules are a union: one allow-all policy opens a pod another restricts.
		policy("a", "open-too", `{"podSelector":{"matchLabels":{"app":"open"}},"policyTypes":["Egress"]}`),
		policy("a", "cidr", `{"podSelector":{"matchLabels":{"app":"cidr"}},"policyTypes":["Ingress","Egress"],"egress":[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0","except":["10.0.0.0/8"]}}]}]}`),
		policy("a", "ports", `{"podSelector":{"matchLabels":{"app":"ports"}},"policyTypes":["Ingress","Egress"],"egress":[{"ports":[{"port":443}]}]}`),
	)
	r := Build(ps, pol, nil, Options{Now: now, All: true})
	if w := find(t, r, "deny-rs"); w.Status != Covered || w.Egress.AnyAddress != 0 {
		t.Fatalf("%+v", w)
	}
	if w := find(t, r, "open-rs"); w.Status != Uncovered || w.Ingress.AllowAll != 1 || w.Egress.AllowAll != 1 || w.Egress.Open != 0 || len(w.Reasons) != 1 {
		t.Fatalf("%+v", w)
	}
	for _, n := range []string{"cidr-rs", "ports-rs"} {
		if w := find(t, r, n); w.Status != Covered || w.Egress.Restricted != 1 || w.Egress.AnyAddress != 1 || w.Ingress.AnyAddress != 0 {
			t.Fatalf("%s %+v", n, w)
		}
	}
}

func TestSelectorExpressions(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "front"}
	for _, c := range []struct {
		sel            string
		matched, valid bool
	}{
		{`{}`, true, true},
		{`{"matchLabels":{"app":"web"}}`, true, true},
		{`{"matchLabels":{"app":"web","tier":"back"}}`, false, true},
		{`{"matchLabels":{"missing":""}}`, false, true},
		{`{"matchExpressions":[{"key":"app","operator":"In","values":["db","web"]}]}`, true, true},
		{`{"matchExpressions":[{"key":"nope","operator":"In","values":[""]}]}`, false, true},
		{`{"matchExpressions":[{"key":"app","operator":"NotIn","values":["web"]}]}`, false, true},
		{`{"matchExpressions":[{"key":"nope","operator":"NotIn","values":["web"]}]}`, true, true},
		{`{"matchExpressions":[{"key":"tier","operator":"Exists"}]}`, true, true},
		{`{"matchExpressions":[{"key":"tier","operator":"DoesNotExist"}]}`, false, true},
		{`{"matchLabels":{"app":"web"},"matchExpressions":[{"key":"tier","operator":"DoesNotExist"}]}`, false, true},
		{`{"matchExpressions":[{"key":"app","operator":"Like","values":["w"]}]}`, false, false},
	} {
		var s Selector
		if err := json.Unmarshal([]byte(c.sel), &s); err != nil {
			t.Fatal(err)
		}
		if m, v := s.matches(labels); m != c.matched || v != c.valid {
			t.Fatalf("%s: got %v %v", c.sel, m, v)
		}
	}
}

func TestBadSelectorIsAGapNotASilentPass(t *testing.T) {
	r := Build(pods(t, pod("a", "p", "x")), policies(t,
		policy("a", "odd", `{"podSelector":{"matchExpressions":[{"key":"app","operator":"Like"}]},"policyTypes":["Egress"]}`)), nil, Options{Now: now})
	if r.Workloads[0].Status != Uncovered || len(r.Gaps) != 2 || !strings.Contains(r.Gaps[0], "a/odd") {
		t.Fatalf("%+v %+v", r.Workloads, r.Gaps)
	}
}

func TestPublicTrafficDrivesAttentionAndOrder(t *testing.T) {
	ps := pods(t,
		pod("a", "quiet-1", "quiet"), pod("a", "talk-1", "talk"), pod("b", "in-1", "in"), pod("c", "safe-1", "safe"),
		`{"metadata":{"namespace":"a","name":"node-agent"},"spec":{"hostNetwork":true}}`,
		`{"metadata":{"namespace":"d","name":"bare"},"spec":{}}`,
	)
	pol := policies(t, policy("c", "deny", `{"podSelector":{},"policyTypes":["Ingress","Egress"]}`))
	old := flow("a", "quiet-1", "quiet-rs", "203.0.113.1", "egress", 999)
	old.ObservedAt = now.Add(-48 * time.Hour)
	recs := []flowlog.Record{
		flow("a", "talk-1", "talk-rs", "203.0.113.1", "egress", 100),
		flow("a", "talk-1", "talk-rs", "203.0.113.1", "egress", 100),
		flow("a", "talk-old", "talk-rs", "203.0.113.2", "egress", 50), // replaced pod
		flow("a", "talk-1", "talk-rs", "10.0.0.1", "egress", 5000),    // private: not public traffic
		flow("b", "in-1", "in-rs", "198.51.100.4", "ingress", 10),
		flow("c", "safe-1", "safe-rs", "203.0.113.3", "egress", 7000), // restricted: no attention
		flow("a", "node-agent", "", "203.0.113.9", "egress", 1),       // hostNetwork: excluded
		old,
	}
	r := Build(ps, pol, recs, Options{Now: now, All: true})
	talk := find(t, r, "talk-rs")
	if !talk.Attention || talk.PublicEgress.Peers != 2 || talk.PublicEgress.Bytes != 250 {
		t.Fatalf("%+v", talk)
	}
	if in := find(t, r, "in-rs"); !in.Attention || in.PublicIn.Peers != 1 || in.PublicEgress.Peers != 0 {
		t.Fatalf("%+v", in)
	}
	if safe := find(t, r, "safe-rs"); safe.Attention || safe.PublicEgress.Peers != 1 {
		t.Fatalf("%+v", safe)
	}
	if q := find(t, r, "quiet-rs"); q.Attention || q.PublicEgress.Peers != 0 {
		t.Fatalf("out-of-window rows must not count: %+v", q)
	}
	if bare := find(t, r, "bare"); bare.Kind != "Pod" {
		t.Fatalf("%+v", bare)
	}
	var order []string
	for _, w := range r.Workloads {
		order = append(order, w.Name)
	}
	if got := strings.Join(order, ","); got != "talk-rs,in-rs,quiet-rs,bare,safe-rs" {
		t.Fatalf("order %s", got)
	}
	if r.Summary.HostNetworkPods != 1 || r.Summary.Pods != 5 || r.Summary.Attention != 2 || r.FlowRecords != 6 {
		t.Fatalf("%+v %d", r.Summary, r.FlowRecords)
	}
	if strings.Join(r.NoPolicyNS, ",") != "a,b,d" {
		t.Fatalf("%v", r.NoPolicyNS)
	}
	cut := Build(ps, pol, recs, Options{Now: now, Limit: 1, Truncated: true})
	if len(cut.Workloads) != 1 || cut.Total != 4 || !cut.ListCut || !cut.Truncated || len(cut.Gaps) != 1 {
		t.Fatalf("%+v", cut)
	}
}

func TestEmptyClusterAndBadJSON(t *testing.T) {
	r := Build(nil, nil, nil, Options{})
	if r.Schema != Schema || r.Workloads == nil || r.NoPolicyNS == nil || len(r.Gaps) != 1 {
		t.Fatalf("%+v", r)
	}
	if _, err := ParsePods(raw([]string{`{"metadata":[]}`})); err == nil {
		t.Fatal("want decode error")
	}
	if _, err := ParsePolicies(raw([]string{`[]`})); err == nil {
		t.Fatal("want decode error")
	}
}
