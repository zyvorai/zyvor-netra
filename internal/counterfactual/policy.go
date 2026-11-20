// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// Policy is a network policy as it would be evaluated. It is a
// simplified, self-contained representation: the counterfactual does not
// need the full expressiveness of a CiliumNetworkPolicy, only the parts
// that determine allow/deny on an observed flow.
//
// A Policy is either:
//   - Non-lockdown: default allow, with a list of Deny rules that block
//     specific traffic.
//   - Lockdown: default deny, with a list of Allow rules that permit
//     specific traffic. This models Netra's lockdown quarantine.
type Policy struct {
	Name     string `json:"name"`
	Lockdown bool   `json:"lockdown,omitempty"`
	Deny     []Rule `json:"deny,omitempty"`
	Allow    []Rule `json:"allow,omitempty"`
}

// RuleKind identifies the type of a rule.
type RuleKind string

const (
	RuleCIDR RuleKind = "cidr"
	RulePort RuleKind = "port"
	RuleDNS  RuleKind = "dns"
	RuleSNI  RuleKind = "sni"
)

// Rule is one matching condition. The fields that are meaningful depend
// on Kind: RuleCIDR uses CIDRs; RulePort uses Protocol+Port; RuleDNS and
// RuleSNI use Names (exact match; wildcards are deliberately not
// supported — see the package doc and TestLockdownDeniesDNSWhenNotExcepted).
// Direction applies to all kinds: "ingress", "egress", or "both" (empty
// defaults to "both").
type Rule struct {
	Kind      RuleKind `json:"kind"`
	Direction string   `json:"direction,omitempty"`
	CIDRs     []string `json:"cidrs,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	Port      int      `json:"port,omitempty"`
	Names     []string `json:"names,omitempty"`
}

// compiled is the parsed form of a Rule, built once when a Policy is
// validated and used during evaluation.
type compiled struct {
	rule      Rule
	direction Direction // empty means both
	cidrs     []netip.Prefix
	protocol  Protocol
	port      uint16
	names     []string // lowercased
}

// Validate parses and checks a Policy, returning a compiled form ready
// for evaluation. Call once per policy, not once per flow.
func (p *Policy) Validate() (*CompiledPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("counterfactual: nil policy")
	}
	cp := &CompiledPolicy{name: p.Name, lockdown: p.Lockdown}
	for i, r := range p.Deny {
		c, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("deny[%d]: %w", i, err)
		}
		cp.deny = append(cp.deny, c)
	}
	for i, r := range p.Allow {
		c, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("allow[%d]: %w", i, err)
		}
		cp.allow = append(cp.allow, c)
	}
	return cp, nil
}

func compileRule(r Rule) (compiled, error) {
	c := compiled{rule: r}

	switch r.Direction {
	case "", "both":
		c.direction = ""
	case string(DirectionIngress):
		c.direction = DirectionIngress
	case string(DirectionEgress):
		c.direction = DirectionEgress
	default:
		return c, fmt.Errorf("invalid direction %q", r.Direction)
	}

	switch r.Kind {
	case RuleCIDR:
		if len(r.CIDRs) == 0 {
			return c, fmt.Errorf("cidr rule requires cidrs")
		}
		for _, s := range r.CIDRs {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return c, fmt.Errorf("parse cidr %q: %w", s, err)
			}
			c.cidrs = append(c.cidrs, pfx.Masked())
		}
	case RulePort:
		if r.Port <= 0 || r.Port > 65535 {
			return c, fmt.Errorf("port rule requires port in [1, 65535], got %d", r.Port)
		}
		c.port = uint16(r.Port)
		switch strings.ToLower(r.Protocol) {
		case "", "any":
			c.protocol = ProtocolAny
		case "tcp":
			c.protocol = ProtocolTCP
		case "udp":
			c.protocol = ProtocolUDP
		default:
			return c, fmt.Errorf("invalid protocol %q", r.Protocol)
		}
	case RuleDNS, RuleSNI:
		if len(r.Names) == 0 {
			return c, fmt.Errorf("%s rule requires names", r.Kind)
		}
		for _, n := range r.Names {
			if strings.TrimSpace(n) == "" {
				return c, fmt.Errorf("empty name")
			}
			c.names = append(c.names, strings.ToLower(strings.TrimSpace(n)))
		}
	default:
		return c, fmt.Errorf("invalid rule kind %q", r.Kind)
	}
	return c, nil
}

// CompiledPolicy is a parsed Policy, ready for evaluation. Construct it
// via Policy.Validate.
type CompiledPolicy struct {
	name     string
	lockdown bool
	deny     []compiled
	allow    []compiled
}

func (c *CompiledPolicy) Name() string   { return c.name }
func (c *CompiledPolicy) Lockdown() bool { return c.lockdown }

// Verdict is the outcome of evaluating a policy against one flow.
type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictDeny
)

func (v Verdict) String() string {
	if v == VerdictDeny {
		return "deny"
	}
	return "allow"
}

// Reason describes why a verdict was reached.
type Reason struct {
	// RuleIndex is the index of the matching rule in its section (deny or
	// allow). -1 when the verdict is from the default.
	RuleIndex int `json:"ruleIndex"`
	// Section is "deny", "allow", or "default".
	Section string `json:"section"`
	// Rule is the matching rule. Zero value when Section is "default".
	Rule Rule `json:"rule"`
}

// Describe returns a human-readable summary of the reason.
func (r Reason) Describe() string {
	if r.Section == "default" {
		return "default"
	}
	return fmt.Sprintf("%s rule %d: %s", r.Section, r.RuleIndex, describeRule(r.Rule))
}

func describeRule(r Rule) string {
	switch r.Kind {
	case RuleCIDR:
		return fmt.Sprintf("cidr %s %s", orBoth(r.Direction), strings.Join(r.CIDRs, ","))
	case RulePort:
		return fmt.Sprintf("port %s %s/%d", orBoth(r.Direction), orAny(r.Protocol), r.Port)
	case RuleDNS:
		return fmt.Sprintf("dns %s %s", orBoth(r.Direction), strings.Join(r.Names, ","))
	case RuleSNI:
		return fmt.Sprintf("sni %s %s", orBoth(r.Direction), strings.Join(r.Names, ","))
	}
	return string(r.Kind)
}

func orBoth(s string) string {
	if s == "" {
		return "both"
	}
	return s
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

// Evaluate runs the policy against one flow and returns the verdict and
// reason.
//
// Semantics, in order:
//  1. If lockdown: try Allow rules in order. First match permits. If none
//     match, deny.
//  2. If not lockdown: try Deny rules in order. First match denies. If
//     none match, allow.
//
// A rule matches a flow only when both the direction and the rule's own
// conditions are satisfied. A rule with Direction "" matches either
// direction.
func (c *CompiledPolicy) Evaluate(f Flow) (Verdict, Reason) {
	if c.lockdown {
		for i, r := range c.allow {
			if matchesCompiled(r, f) {
				return VerdictAllow, Reason{Section: "allow", RuleIndex: i, Rule: r.rule}
			}
		}
		return VerdictDeny, Reason{Section: "default", RuleIndex: -1}
	}
	for i, r := range c.deny {
		if matchesCompiled(r, f) {
			return VerdictDeny, Reason{Section: "deny", RuleIndex: i, Rule: r.rule}
		}
	}
	return VerdictAllow, Reason{Section: "default", RuleIndex: -1}
}

func matchesCompiled(c compiled, f Flow) bool {
	if c.direction != "" && c.direction != f.Direction {
		return false
	}

	switch c.rule.Kind {
	case RuleCIDR:
		ip := f.RemoteIP()
		if !ip.IsValid() {
			return false
		}
		for _, p := range c.cidrs {
			// netip.Prefix.Contains requires the same address family; a
			// v4 flow against a v6 prefix simply does not match.
			if p.Addr().Is4() != ip.Is4() {
				continue
			}
			if p.Contains(ip) {
				return true
			}
		}
		return false

	case RulePort:
		if c.protocol != ProtocolAny && string(c.protocol) != string(f.Protocol) {
			return false
		}
		return f.RemotePort() == c.port

	case RuleDNS:
		if f.DNSName == "" {
			return false
		}
		return slices.Contains(c.names, strings.ToLower(f.DNSName))

	case RuleSNI:
		if f.TLSSNI == "" {
			return false
		}
		return slices.Contains(c.names, strings.ToLower(f.TLSSNI))
	}
	return false
}

// Hash returns a stable SHA-256 hash of the policy as serialized JSON,
// used as the policy fingerprint in a receipt. Two logically identical
// policies with differently ordered rule lists produce the same hash.
func (p *Policy) Hash() (string, error) {
	norm := *p
	norm.Deny = normalizeRules(norm.Deny)
	norm.Allow = normalizeRules(norm.Allow)
	b, err := json.Marshal(&norm)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeRules(in []Rule) []Rule {
	out := make([]Rule, len(in))
	copy(out, in)
	for i := range out {
		out[i].CIDRs = append([]string(nil), out[i].CIDRs...)
		out[i].Names = append([]string(nil), out[i].Names...)
		sort.Strings(out[i].CIDRs)
		sort.Strings(out[i].Names)
		out[i].Kind = RuleKind(strings.ToLower(string(out[i].Kind)))
		out[i].Direction = strings.ToLower(out[i].Direction)
		out[i].Protocol = strings.ToLower(out[i].Protocol)
	}
	// Sort the rules themselves so the hash doesn't depend on the order
	// they were written in — only their content.
	keyed := make([]string, len(out))
	for i, r := range out {
		b, _ := json.Marshal(&r)
		keyed[i] = string(b)
	}
	sort.Sort(&ruleSorter{rules: out, keys: keyed})
	return out
}

// ruleSorter sorts rules by their JSON-serialized form, keeping the
// keys slice in lockstep so the marshal above only happens once.
type ruleSorter struct {
	rules []Rule
	keys  []string
}

func (s *ruleSorter) Len() int { return len(s.rules) }
func (s *ruleSorter) Swap(i, j int) {
	s.rules[i], s.rules[j] = s.rules[j], s.rules[i]
	s.keys[i], s.keys[j] = s.keys[j], s.keys[i]
}
func (s *ruleSorter) Less(i, j int) bool { return s.keys[i] < s.keys[j] }
