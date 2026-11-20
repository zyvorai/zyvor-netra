// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package counterfactual

import (
	"net/netip"
	"testing"
	"time"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

func TestValidateRejectsBadRules(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
	}{
		{"bad direction", Policy{Deny: []Rule{{Kind: RuleCIDR, Direction: "sideways", CIDRs: []string{"10.0.0.0/8"}}}}},
		{"cidr without cidrs", Policy{Deny: []Rule{{Kind: RuleCIDR}}}},
		{"bad cidr", Policy{Deny: []Rule{{Kind: RuleCIDR, CIDRs: []string{"not-a-cidr"}}}}},
		{"port out of range", Policy{Deny: []Rule{{Kind: RulePort, Port: 70000}}}},
		{"bad protocol", Policy{Deny: []Rule{{Kind: RulePort, Port: 80, Protocol: "sctp"}}}},
		{"dns without names", Policy{Deny: []Rule{{Kind: RuleDNS}}}},
		{"sni empty name", Policy{Deny: []Rule{{Kind: RuleSNI, Names: []string{"  "}}}}},
		{"unknown kind", Policy{Deny: []Rule{{Kind: "bogus"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.policy.Validate(); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestEvaluateDenyByCIDR(t *testing.T) {
	p := Policy{
		Name: "deny-external",
		Deny: []Rule{{Kind: RuleCIDR, Direction: "egress", CIDRs: []string{"93.184.0.0/16"}}},
	}
	cp, err := p.Validate()
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	denied := Flow{
		Direction: DirectionEgress,
		SrcIP:     mustAddr(t, "10.0.0.5"),
		DstIP:     mustAddr(t, "93.184.216.34"),
		Protocol:  ProtocolTCP,
	}
	if v, r := cp.Evaluate(denied); v != VerdictDeny {
		t.Fatalf("expected deny, got %s (%s)", v, r.Describe())
	}

	allowedDifferentCIDR := Flow{
		Direction: DirectionEgress,
		SrcIP:     mustAddr(t, "10.0.0.5"),
		DstIP:     mustAddr(t, "8.8.8.8"),
		Protocol:  ProtocolTCP,
	}
	if v, _ := cp.Evaluate(allowedDifferentCIDR); v != VerdictAllow {
		t.Fatalf("expected allow for non-matching CIDR, got %s", v)
	}

	allowedIngress := Flow{
		Direction: DirectionIngress,
		SrcIP:     mustAddr(t, "93.184.216.34"),
		DstIP:     mustAddr(t, "10.0.0.5"),
		Protocol:  ProtocolTCP,
	}
	if v, _ := cp.Evaluate(allowedIngress); v != VerdictAllow {
		t.Fatalf("expected allow for wrong direction, got %s", v)
	}
}

func TestEvaluatePortAnyProtocolMatchesBoth(t *testing.T) {
	p := Policy{Deny: []Rule{{Kind: RulePort, Port: 53}}}
	cp, err := p.Validate()
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	tcp := Flow{Direction: DirectionEgress, DstPort: 53, Protocol: ProtocolTCP}
	udp := Flow{Direction: DirectionEgress, DstPort: 53, Protocol: ProtocolUDP}
	if v, _ := cp.Evaluate(tcp); v != VerdictDeny {
		t.Fatalf("expected deny for tcp/53, got %s", v)
	}
	if v, _ := cp.Evaluate(udp); v != VerdictDeny {
		t.Fatalf("expected deny for udp/53, got %s", v)
	}
}

func TestEvaluatePortSpecificProtocol(t *testing.T) {
	p := Policy{Deny: []Rule{{Kind: RulePort, Port: 53, Protocol: "udp"}}}
	cp, err := p.Validate()
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	tcp := Flow{Direction: DirectionEgress, DstPort: 53, Protocol: ProtocolTCP}
	if v, _ := cp.Evaluate(tcp); v != VerdictAllow {
		t.Fatalf("expected allow for tcp/53 under udp-only rule, got %s", v)
	}
}

func TestLockdownDeniesDNSWhenNotExcepted(t *testing.T) {
	p := Policy{
		Name:     "lockdown",
		Lockdown: true,
		Allow:    []Rule{{Kind: RuleDNS, Names: []string{"api.example.com"}}},
	}
	cp, err := p.Validate()
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	excepted := Flow{Direction: DirectionEgress, DNSName: "api.example.com"}
	if v, _ := cp.Evaluate(excepted); v != VerdictAllow {
		t.Fatalf("expected allow for excepted dns name, got %s", v)
	}

	other := Flow{Direction: DirectionEgress, DNSName: "evil.example.net"}
	if v, r := cp.Evaluate(other); v != VerdictDeny {
		t.Fatalf("expected deny for non-excepted dns name, got %s (%s)", v, r.Describe())
	}

	// Case sensitivity: names are compared lowercased.
	upper := Flow{Direction: DirectionEgress, DNSName: "API.EXAMPLE.COM"}
	if v, _ := cp.Evaluate(upper); v != VerdictAllow {
		t.Fatalf("expected case-insensitive dns match to allow, got %s", v)
	}

	// No wildcard support: a subdomain of an excepted name still denies.
	subdomain := Flow{Direction: DirectionEgress, DNSName: "sub.api.example.com"}
	if v, _ := cp.Evaluate(subdomain); v != VerdictDeny {
		t.Fatalf("expected deny for subdomain (no wildcard support), got %s", v)
	}

	// A flow with no DNS name at all never matches a DNS rule.
	noName := Flow{Direction: DirectionEgress}
	if v, _ := cp.Evaluate(noName); v != VerdictDeny {
		t.Fatalf("expected deny for flow without dns name under lockdown, got %s", v)
	}
}

func TestEvaluateSNIRule(t *testing.T) {
	p := Policy{Deny: []Rule{{Kind: RuleSNI, Names: []string{"tracker.example.com"}}}}
	cp, err := p.Validate()
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	matched := Flow{Direction: DirectionEgress, TLSSNI: "tracker.example.com"}
	if v, _ := cp.Evaluate(matched); v != VerdictDeny {
		t.Fatalf("expected deny, got %s", v)
	}
	unmatched := Flow{Direction: DirectionEgress, TLSSNI: "safe.example.com"}
	if v, _ := cp.Evaluate(unmatched); v != VerdictAllow {
		t.Fatalf("expected allow, got %s", v)
	}
}

func TestHashStableAcrossRuleOrder(t *testing.T) {
	p1 := Policy{
		Name: "p",
		Deny: []Rule{
			{Kind: RuleCIDR, CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}},
			{Kind: RulePort, Port: 53},
		},
	}
	p2 := Policy{
		Name: "p",
		Deny: []Rule{
			{Kind: RulePort, Port: 53},
			{Kind: RuleCIDR, CIDRs: []string{"192.168.0.0/16", "10.0.0.0/8"}},
		},
	}
	h1, err := p1.Hash()
	if err != nil {
		t.Fatalf("hash p1: %v", err)
	}
	h2, err := p2.Hash()
	if err != nil {
		t.Fatalf("hash p2: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected stable hash across rule order, got %s vs %s", h1, h2)
	}

	p3 := p1
	p3.Name = "different"
	h3, err := p3.Hash()
	if err != nil {
		t.Fatalf("hash p3: %v", err)
	}
	if h3 == h1 {
		t.Fatalf("expected different hash for different policy name")
	}
}

func TestReasonDescribe(t *testing.T) {
	p := Policy{Deny: []Rule{{Kind: RulePort, Port: 53, Protocol: "udp"}}}
	cp, err := p.Validate()
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	f := Flow{Direction: DirectionEgress, DstPort: 53, Protocol: ProtocolUDP, Timestamp: time.Now()}
	_, r := cp.Evaluate(f)
	if got := r.Describe(); got == "" || got == "default" {
		t.Fatalf("expected non-default description, got %q", got)
	}
}
