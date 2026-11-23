// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package denysim

import (
	"strings"
	"testing"
)

func TestCheckLockout(t *testing.T) {
	prot, err := ParseProtected("10.96.0.1:443, 10.96.0.10, :30870, ctl.example.com, process:kubelet, 192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		p    Proposal
		risk string
		min  int
	}{
		{"unrelated ip", Proposal{Kind: "ip", Value: "203.0.113.9"}, RiskNoneDetected, 0},
		{"exact apiserver", Proposal{Kind: "ip", Value: "10.96.0.1"}, RiskLikely, 1},
		{"apiserver other port", Proposal{Kind: "ip", Value: "10.96.0.1", Port: 8080}, RiskNoneDetected, 0},
		{"cidr covers resolver", Proposal{Kind: "cidr", Value: "10.96.0.0/16"}, RiskLikely, 2},
		{"v4-mapped v6 cidr", Proposal{Kind: "cidr", Value: "::/0"}, RiskLikely, 1},
		{"catch-all v4", Proposal{Kind: "cidr", Value: "0.0.0.0/0"}, RiskLikely, 2},
		{"port 30870", Proposal{Kind: "port", Value: "30870", Protocol: "tcp"}, RiskLikely, 1},
		{"port 30870 udp (operator entry has no protocol)", Proposal{Kind: "port", Value: "30870", Protocol: "UDP"}, RiskLikely, 1},
		{"dns exact mixed case and trailing dot", Proposal{Kind: "dns", Value: "CTL.example.com."}, RiskLikely, 1},
		{"dns exact", Proposal{Kind: "dns", Value: "ctl.example.com"}, RiskLikely, 1},
		{"dns wildcard", Proposal{Kind: "sni", Value: "*.example.com"}, RiskLikely, 1},
		{"process", Proposal{Kind: "process", Value: "Kubelet"}, RiskLikely, 1},
		{"scoped downgrades", Proposal{Kind: "ip", Value: "10.96.0.1", Namespace: "prod"}, RiskPossible, 1},
		{"in documentation net", Proposal{Kind: "ip", Value: "192.0.2.77"}, RiskLikely, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lo, err := CheckLockout(c.p, prot)
			if err != nil {
				t.Fatal(err)
			}
			if lo.Risk != c.risk || len(lo.Warnings) < c.min {
				t.Fatalf("risk=%s warnings=%v want %s >=%d", lo.Risk, lo.Warnings, c.risk, c.min)
			}
			if lo.Caveat == "" || len(lo.Checked) != len(prot) {
				t.Fatalf("caveat/checked missing: %+v", lo)
			}
		})
	}
}

func TestCheckLockoutRejectsHostile(t *testing.T) {
	for _, p := range []Proposal{
		{Kind: "ip", Value: "not-an-ip"},
		{Kind: "cidr", Value: "10.0.0.0/99"},
		{Kind: "port", Value: "70000"},
		{Kind: "bogus", Value: "x"},
		{Kind: "ip", Value: ""},
	} {
		if _, err := CheckLockout(p, nil); err == nil {
			t.Fatalf("%+v accepted", p)
		}
	}
}

func TestParseProtectedHostile(t *testing.T) {
	for _, raw := range []string{"a b/c", ":0", ":99999", "process:", "bad name!", strings.Repeat("a", 300), "http://x"} {
		if _, err := ParseProtected(raw); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
	if got, err := ParseProtected(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestBuiltinProtected(t *testing.T) {
	env := map[string]string{"KUBERNETES_SERVICE_HOST": "10.43.0.1", "KUBERNETES_SERVICE_PORT": "443"}
	got := BuiltinProtected(func(k string) string { return env[k] }, "# c\nnameserver 10.43.0.10\nnameserver bogus\nsearch x\n", ":30870")
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	for _, want := range []string{"dns (any resolver)", "kube-apiserver", "dns resolver 10.43.0.10", "netra controller listen port"} {
		if !names[want] {
			t.Fatalf("missing %q in %v", want, got)
		}
	}
	// no env, no resolv.conf, odd listen: only the DNS port remains
	if got := BuiltinProtected(func(string) string { return "" }, "", "garbage"); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
