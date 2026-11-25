// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package netpolcoverage answers which workloads no Kubernetes NetworkPolicy
// restricts, per direction, and which of those were seen talking to public
// addresses in the retained flow history. It follows the upstream isolation
// rules: a pod is isolated in a direction only when some policy in its
// namespace selects it and lists that direction in policyTypes, and the allowed
// set is the union of the rules of every such policy.
//
// It reads only what it is handed (pod labels, NetworkPolicy specs, flow
// records). It evaluates no other policy kind, does not say whether the CNI
// enforces anything, and creates, changes or suggests no policy.
package netpolcoverage

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/flowdrift"
	"github.com/zyvorai/netra/internal/flowlog"
)

// Schema names the report.
const Schema = "netra-netpol-coverage/1"

// Bounds and defaults.
const (
	DefaultWindow = 24 * time.Hour
	MinWindow     = time.Minute
	MaxWindow     = 14 * 24 * time.Hour
	DefaultLimit  = 200
	MaxLimit      = 1000
	maxGapNotes   = 20
)

// Workload coverage states, worst first.
const (
	Uncovered = "uncovered" // every pod accepts any traffic in both directions
	Partial   = "partial"   // some pod is unrestricted in some direction
	Covered   = "covered"   // every pod is restricted in both directions
)

// Expression is one matchExpressions entry of a label selector.
type Expression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// Selector is a Kubernetes label selector. The zero value selects everything.
type Selector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []Expression      `json:"matchExpressions"`
}

// Peer is one entry of a rule's from or to list.
type Peer struct {
	IPBlock *struct {
		CIDR   string   `json:"cidr"`
		Except []string `json:"except"`
	} `json:"ipBlock"`
	PodSelector       *Selector `json:"podSelector"`
	NamespaceSelector *Selector `json:"namespaceSelector"`
}

// Rule is one ingress or egress rule.
type Rule struct {
	From  []Peer            `json:"from"`
	To    []Peer            `json:"to"`
	Ports []json.RawMessage `json:"ports"`
}

// Policy is the part of a networking.k8s.io/v1 NetworkPolicy that decides
// isolation.
type Policy struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		PodSelector Selector `json:"podSelector"`
		PolicyTypes []string `json:"policyTypes"`
		Ingress     []Rule   `json:"ingress"`
		Egress      []Rule   `json:"egress"`
	} `json:"spec"`
}

// Pod is the part of a Pod that coverage needs.
type Pod struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
		Owners    []struct {
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			Controller bool   `json:"controller"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		HostNetwork bool `json:"hostNetwork"`
	} `json:"spec"`
}

// ParsePolicies decodes NetworkPolicy list items.
func ParsePolicies(items []json.RawMessage) ([]Policy, error) {
	return parse[Policy](items, "NetworkPolicy")
}

// ParsePods decodes Pod list items.
func ParsePods(items []json.RawMessage) ([]Pod, error) { return parse[Pod](items, "Pod") }

func parse[T any](items []json.RawMessage, kind string) ([]T, error) {
	out := make([]T, 0, len(items))
	for _, raw := range items {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("decode %s: %w", kind, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// matches reports whether labels satisfy s. valid is false for an operator
// Kubernetes does not define; such a selector matches nothing.
func (s Selector) matches(labels map[string]string) (matched, valid bool) {
	matched = true
	for k, v := range s.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			matched = false
		}
	}
	for _, e := range s.MatchExpressions {
		got, ok := labels[e.Key]
		var m bool
		switch e.Operator {
		case "In":
			m = ok && slices.Contains(e.Values, got)
		case "NotIn":
			m = !ok || !slices.Contains(e.Values, got)
		case "Exists":
			m = ok
		case "DoesNotExist":
			m = !ok
		default:
			return false, false
		}
		matched = matched && m
	}
	return matched, true
}

// directions reports which directions p isolates, applying the API default:
// Ingress always, Egress only when the policy has egress rules.
func (p Policy) directions() (ingress, egress bool) {
	if len(p.Spec.PolicyTypes) == 0 {
		return true, len(p.Spec.Egress) > 0
	}
	for _, t := range p.Spec.PolicyTypes {
		switch t {
		case "Ingress":
			ingress = true
		case "Egress":
			egress = true
		}
	}
	return ingress, egress
}

// ruleReach classifies a direction's rules: all means some rule has neither
// peers nor ports, so every connection is allowed; anyAddress means some rule
// names 0.0.0.0/0 or ::/0.
func ruleReach(rules []Rule, egress bool) (all, anyAddress bool) {
	for _, r := range rules {
		peers := r.From
		if egress {
			peers = r.To
		}
		if len(peers) == 0 {
			if len(r.Ports) == 0 {
				all = true
			}
			anyAddress = true
			continue
		}
		for _, p := range peers {
			if p.IPBlock != nil && (p.IPBlock.CIDR == "0.0.0.0/0" || p.IPBlock.CIDR == "::/0") {
				anyAddress = true
			}
		}
	}
	return all, anyAddress
}

// DirectionCounts counts a workload's pods by what policy does in one
// direction.
type DirectionCounts struct {
	Open     int `json:"open"`     // no policy selects the pod for this direction
	AllowAll int `json:"allowAll"` // selected, but a rule allows everything
	// Restricted pods are selected and no rule allows everything.
	Restricted int `json:"restricted"`
	// AnyAddress counts restricted pods whose rules still allow some traffic
	// to or from any address (a rule with only ports, or 0.0.0.0/0).
	AnyAddress int `json:"restrictedButAnyAddress"`
}

// Unrestricted is the number of pods that accept any traffic this way.
func (d DirectionCounts) Unrestricted() int { return d.Open + d.AllowAll }

// Workload is one row of the report.
type Workload struct {
	Namespace    string          `json:"namespace"`
	Kind         string          `json:"kind,omitempty"`
	Name         string          `json:"name"`
	Pods         int             `json:"pods"`
	Status       string          `json:"status"`
	Ingress      DirectionCounts `json:"ingress"`
	Egress       DirectionCounts `json:"egress"`
	Policies     []string        `json:"policies,omitempty"` // policies selecting any of its pods
	PublicEgress PublicTraffic   `json:"publicEgress"`
	PublicIn     PublicTraffic   `json:"publicIngress"`
	// Attention says an unrestricted direction was seen talking to a public
	// address in the window.
	Attention bool     `json:"attention,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
}

// PublicTraffic summarises flow history toward or from public addresses.
type PublicTraffic struct {
	Peers int    `json:"peers"`
	Bytes uint64 `json:"bytes"`
}

// Summary totals every workload in scope, listed or not.
type Summary struct {
	Policies            int `json:"policies"`
	Pods                int `json:"pods"`
	HostNetworkPods     int `json:"hostNetworkPods"` // excluded: policy behaviour for them is undefined
	Workloads           int `json:"workloads"`
	Uncovered           int `json:"uncovered"`
	Partial             int `json:"partial"`
	Covered             int `json:"covered"`
	Attention           int `json:"attention"`
	IngressUnrestricted int `json:"ingressUnrestrictedPods"`
	EgressUnrestricted  int `json:"egressUnrestrictedPods"`
}

// Report is the answer to GET /api/v1/insights/netpol-coverage.
type Report struct {
	Schema      string     `json:"schema"`
	Now         string     `json:"now"`
	FlowStart   string     `json:"flowStart"`
	FlowRecords int        `json:"flowRecords"` // history records joined; zero means no traffic evidence
	Truncated   bool       `json:"truncated"`
	Summary     Summary    `json:"summary"`
	NoPolicyNS  []string   `json:"namespacesWithoutPolicy"`
	Workloads   []Workload `json:"workloads"`
	Total       int        `json:"total"` // rows before the limit
	ListCut     bool       `json:"listTruncated"`
	Gaps        []string   `json:"gaps"`
	Limitations []string   `json:"limitations"`
}

// Options select what is listed.
type Options struct {
	Now    time.Time
	Window time.Duration
	// All also lists covered workloads.
	All       bool
	Limit     int
	Truncated bool // the flow record set was cut
}

// Limitations returned with every report.
func Limitations() []string {
	return []string{
		"Only networking.k8s.io/v1 NetworkPolicy is read. CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, Calico policies, AdminNetworkPolicy and Netra's own deny rules are not counted, so a workload shown open may be restricted by one of them.",
		"Whether the cluster's CNI enforces NetworkPolicy at all is not checked.",
		"Restricted means isolated by some policy, not that the rules are tight. This is not a connectivity simulation: it does not say which observed flows a rule would drop.",
		"Pods with hostNetwork are excluded because Kubernetes leaves policy behaviour for them undefined. Finished pods are not counted.",
		"Public traffic comes from retained flow history joined by namespace and pod or workload name; no traffic shown is not proof there was none.",
		"Read-only: no policy is created, changed or suggested.",
	}
}

type rowKey struct{ ns, kind, name string }

type row struct {
	w        Workload
	policies map[string]bool
	egPeers  map[string]bool
	inPeers  map[string]bool
}

// Build joins pods, policies and flow records into the coverage report. pods
// and policies must already be limited to what the caller may see.
func Build(pods []Pod, policies []Policy, recs []flowlog.Record, o Options) Report {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	o.Now = o.Now.UTC()
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	if o.Limit <= 0 {
		o.Limit = DefaultLimit
	}
	if o.Limit > MaxLimit {
		o.Limit = MaxLimit
	}
	start := o.Now.Add(-o.Window)
	rep := Report{
		Schema: Schema, Now: o.Now.Format(time.RFC3339), FlowStart: start.Format(time.RFC3339), Truncated: o.Truncated,
		NoPolicyNS: []string{}, Workloads: []Workload{}, Gaps: []string{}, Limitations: Limitations(),
	}
	rep.Summary.Policies = len(policies)
	byNS := map[string][]Policy{}
	for _, p := range policies {
		byNS[p.Metadata.Namespace] = append(byNS[p.Metadata.Namespace], p)
	}

	rows := map[rowKey]*row{}
	podRow := map[[2]string]*row{}  // namespace, pod
	nameRow := map[[2]string]*row{} // namespace, workload name
	nsSeen := map[string]bool{}
	badSelector := map[string]bool{}
	for _, pod := range pods {
		ns := pod.Metadata.Namespace
		if pod.Spec.HostNetwork {
			rep.Summary.HostNetworkPods++
			continue
		}
		nsSeen[ns] = true
		rep.Summary.Pods++
		kind, name := owner(pod)
		k := rowKey{ns, kind, name}
		r := rows[k]
		if r == nil {
			r = &row{w: Workload{Namespace: ns, Kind: kind, Name: name}, policies: map[string]bool{}, egPeers: map[string]bool{}, inPeers: map[string]bool{}}
			rows[k] = r
		}
		r.w.Pods++
		podRow[[2]string{ns, pod.Metadata.Name}] = r
		nameRow[[2]string{ns, name}] = r

		var inSel, egSel, inAll, egAll, inAny, egAny bool
		for _, p := range byNS[ns] {
			matched, valid := p.Spec.PodSelector.matches(pod.Metadata.Labels)
			if !valid {
				badSelector[ns+"/"+p.Metadata.Name] = true
			}
			if !matched {
				continue
			}
			in, eg := p.directions()
			if !in && !eg {
				continue
			}
			r.policies[p.Metadata.Name] = true
			if in {
				all, anyAddr := ruleReach(p.Spec.Ingress, false)
				inSel, inAll, inAny = true, inAll || all, inAny || anyAddr
			}
			if eg {
				all, anyAddr := ruleReach(p.Spec.Egress, true)
				egSel, egAll, egAny = true, egAll || all, egAny || anyAddr
			}
		}
		count(&r.w.Ingress, inSel, inAll, inAny)
		count(&r.w.Egress, egSel, egAll, egAny)
	}

	for _, rec := range recs {
		if rec.ObservedAt.Before(start) || rec.ObservedAt.After(o.Now) || rec.Namespace == "" {
			continue
		}
		r := podRow[[2]string{rec.Namespace, rec.Pod}]
		if r == nil && rec.WorkloadName != "" {
			// A replaced pod: attribute its history to the same workload.
			r = nameRow[[2]string{rec.Namespace, rec.WorkloadName}]
		}
		if r == nil {
			continue
		}
		rep.FlowRecords++
		if flowdrift.PeerClass(rec.Peer) != "public" {
			continue
		}
		switch strings.ToLower(rec.Direction) {
		case "egress":
			r.egPeers[rec.Peer] = true
			r.w.PublicEgress.Bytes += rec.Bytes
		case "ingress":
			r.inPeers[rec.Peer] = true
			r.w.PublicIn.Bytes += rec.Bytes
		}
	}

	for ns := range nsSeen {
		if len(byNS[ns]) == 0 {
			rep.NoPolicyNS = append(rep.NoPolicyNS, ns)
		}
	}
	sort.Strings(rep.NoPolicyNS)

	for _, r := range rows {
		w := r.w
		w.PublicEgress.Peers, w.PublicIn.Peers = len(r.egPeers), len(r.inPeers)
		for p := range r.policies {
			w.Policies = append(w.Policies, p)
		}
		sort.Strings(w.Policies)
		switch {
		case w.Ingress.Unrestricted() == w.Pods && w.Egress.Unrestricted() == w.Pods:
			w.Status = Uncovered
			rep.Summary.Uncovered++
		case w.Ingress.Unrestricted() > 0 || w.Egress.Unrestricted() > 0:
			w.Status = Partial
			rep.Summary.Partial++
		default:
			w.Status = Covered
			rep.Summary.Covered++
		}
		if w.Egress.Unrestricted() > 0 && w.PublicEgress.Peers > 0 {
			w.Attention = true
			w.Reasons = append(w.Reasons, fmt.Sprintf("unrestricted egress and %d public destination(s) seen", w.PublicEgress.Peers))
		}
		if w.Ingress.Unrestricted() > 0 && w.PublicIn.Peers > 0 {
			w.Attention = true
			w.Reasons = append(w.Reasons, fmt.Sprintf("unrestricted ingress and %d public source(s) seen", w.PublicIn.Peers))
		}
		if w.Ingress.AllowAll > 0 || w.Egress.AllowAll > 0 {
			w.Reasons = append(w.Reasons, "a policy selects it but has a rule that allows everything")
		}
		if w.Attention {
			rep.Summary.Attention++
		}
		rep.Summary.Workloads++
		rep.Summary.IngressUnrestricted += w.Ingress.Unrestricted()
		rep.Summary.EgressUnrestricted += w.Egress.Unrestricted()
		if o.All || w.Status != Covered {
			rep.Workloads = append(rep.Workloads, w)
		}
	}
	sort.Slice(rep.Workloads, func(i, j int) bool { return less(rep.Workloads[i], rep.Workloads[j]) })
	rep.Total = len(rep.Workloads)
	if len(rep.Workloads) > o.Limit {
		rep.Workloads, rep.ListCut = rep.Workloads[:o.Limit], true
	}

	var bad []string
	for p := range badSelector {
		bad = append(bad, p)
	}
	sort.Strings(bad)
	for i, p := range bad {
		if i == maxGapNotes {
			rep.Gaps = append(rep.Gaps, fmt.Sprintf("%d more policies have selectors that could not be evaluated", len(bad)-i))
			break
		}
		rep.Gaps = append(rep.Gaps, "policy "+p+" has an unknown selector operator and was treated as selecting nothing")
	}
	if rep.FlowRecords == 0 {
		rep.Gaps = append(rep.Gaps, "no flow history joined to these pods in the window, so public traffic is unknown")
	}
	if o.Truncated {
		rep.Gaps = append(rep.Gaps, "the flow history was cut to its row bound, so public traffic counts may be low")
	}
	return rep
}

func count(d *DirectionCounts, selected, all, anyAddress bool) {
	switch {
	case !selected:
		d.Open++
	case all:
		d.AllowAll++
	default:
		d.Restricted++
		if anyAddress {
			d.AnyAddress++
		}
	}
}

// owner names a pod's workload the way the rest of Netra does: the controlling
// owner reference, else the pod itself.
func owner(p Pod) (kind, name string) {
	for _, o := range p.Metadata.Owners {
		if o.Controller || kind == "" {
			kind, name = o.Kind, o.Name
		}
		if o.Controller {
			break
		}
	}
	if name == "" {
		return "Pod", p.Metadata.Name
	}
	return kind, name
}

var statusRank = map[string]int{Uncovered: 0, Partial: 1, Covered: 2}

// less lists workloads needing attention first, then by coverage, then by the
// public bytes seen.
func less(a, b Workload) bool {
	if a.Attention != b.Attention {
		return a.Attention
	}
	if statusRank[a.Status] != statusRank[b.Status] {
		return statusRank[a.Status] < statusRank[b.Status]
	}
	x, y := a.PublicEgress.Bytes+a.PublicIn.Bytes, b.PublicEgress.Bytes+b.PublicIn.Bytes
	if x != y {
		return x > y
	}
	return a.Namespace+"|"+a.Name+"|"+a.Kind < b.Namespace+"|"+b.Name+"|"+b.Kind
}
