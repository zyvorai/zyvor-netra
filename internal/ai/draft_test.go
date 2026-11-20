// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ai

import "testing"

func TestDraftRuleIP(t *testing.T) {
	d := DraftRule("please deny 10.9.8.7 egress")
	if !d.Understood || d.Kind != "ip" {
		t.Fatalf("%+v", d)
	}
	if d.Body["ip"] != "10.9.8.7" {
		t.Fatalf("body=%v", d.Body)
	}
}

func TestDraftRuleCIDR(t *testing.T) {
	d := DraftRule("block 10.0.0.0/8 ingress")
	if !d.Understood || d.Kind != "cidr" {
		t.Fatalf("%+v", d)
	}
	if d.Body["direction"] != "ingress" {
		t.Fatalf("dir=%v", d.Body["direction"])
	}
}

func TestDraftRuleDNSAndPortAndRate(t *testing.T) {
	dns := DraftRule("deny dns malware.example")
	if !dns.Understood || dns.Kind != "dns" {
		t.Fatalf("dns=%+v", dns)
	}
	port := DraftRule("deny tcp port 445")
	if !port.Understood || port.Kind != "port" {
		t.Fatalf("port=%+v", port)
	}
	rate := DraftRule("rate limit 1.2.3.4 to 100 pps")
	if !rate.Understood || rate.Kind != "rate" {
		t.Fatalf("rate=%+v", rate)
	}
}

func TestDraftRuleAllowException(t *testing.T) {
	d := DraftRule("allow 10.0.0.5")
	if !d.Understood || d.Kind != "allow" || d.ApplyPath != "/api/v1/ebpf/allow" {
		t.Fatalf("%+v", d)
	}
}

func TestDraftRuleAllowCIDR(t *testing.T) {
	d := DraftRule("allow 10.0.0.0/24 egress")
	if !d.Understood || d.Kind != "cidr-allow" || d.ApplyPath != "/api/v1/ebpf/allow-cidr" || d.Body["cidr"] != "10.0.0.0/24" {
		t.Fatalf("%+v", d)
	}
	deny := DraftRule("deny 10.0.0.0/8 ingress")
	if deny.Kind != "cidr" {
		t.Fatalf("deny regressed: %+v", deny)
	}
}

func TestDraftRuleAllowPort(t *testing.T) {
	d := DraftRule("allow port 443")
	if !d.Understood || d.Kind != "port-allow" || d.ApplyPath != "/api/v1/ebpf/allow-port" || d.Body["port"] != uint16(443) {
		t.Fatalf("%+v", d)
	}
	udp := DraftRule("allow udp port 53")
	if !udp.Understood || udp.Kind != "port-allow" || udp.Body["protocol"] != "UDP" {
		t.Fatalf("%+v", udp)
	}
	deny := DraftRule("deny port 445")
	if deny.Kind != "port" || deny.ApplyPath != "/api/v1/ebpf/port" {
		t.Fatalf("deny regressed: %+v", deny)
	}
}

func TestDraftRuleAllowUID(t *testing.T) {
	d := DraftRule("except uid 1000")
	if !d.Understood || d.Kind != "uid-allow" || d.ApplyPath != "/api/v1/ebpf/allow-uid" || d.Body["uid"] != uint32(1000) {
		t.Fatalf("%+v", d)
	}
	root := DraftRule("allow uid 0")
	if !root.Understood || root.Kind != "uid-allow" || root.Confidence != "medium" {
		t.Fatalf("root=%+v", root)
	}
	deny := DraftRule("deny uid 1000")
	if deny.Kind != "uid" {
		t.Fatalf("deny regressed: %+v", deny)
	}
}

func TestDraftRuleAllowProcess(t *testing.T) {
	d := DraftRule("allow process coredns")
	if !d.Understood || d.Kind != "process-allow" || d.ApplyPath != "/api/v1/ebpf/allow-process" || d.Body["name"] != "coredns" {
		t.Fatalf("%+v", d)
	}
	deny := DraftRule("deny process curl")
	if deny.Kind != "process" || deny.Body["name"] != "curl" {
		t.Fatalf("deny regressed: %+v", deny)
	}
}

func TestDraftRuleIPv6(t *testing.T) {
	deny := DraftRule("deny 2001:db8::1")
	if !deny.Understood || deny.Kind != "ip" || deny.Body["ip"] != "2001:db8::1" {
		t.Fatalf("deny=%+v", deny)
	}
	allow := DraftRule("allow 2001:db8::55")
	if !allow.Understood || allow.Kind != "allow" || allow.ApplyPath != "/api/v1/ebpf/allow" || allow.Body["ip"] != "2001:db8::55" {
		t.Fatalf("allow=%+v", allow)
	}
	rate := DraftRule("rate limit 2001:db8::99 to 500 pps")
	if !rate.Understood || rate.Kind != "rate" || rate.Body["destination"] != "2001:db8::99" {
		t.Fatalf("rate=%+v", rate)
	}
	cidr := DraftRule("block 2001:db8::/32 ingress")
	if !cidr.Understood || cidr.Kind != "cidr" || cidr.Body["cidr"] != "2001:db8::/32" {
		t.Fatalf("cidr=%+v", cidr)
	}
}

func TestDraftRuleRefusesDiagnostics(t *testing.T) {
	d := DraftRule("why is DNS failing?")
	if d.Understood {
		t.Fatalf("should not draft a rule from a diagnostic question: %+v", d)
	}
}

func TestFingerprintStableAcrossCounterChatter(t *testing.T) {
	a := Snapshot{Mode: "observe", HealthScore: 91, Anomalies: []Finding{{Kind: "dns-failure", Message: "x"}}}
	b := Snapshot{Mode: "observe", HealthScore: 94, Packets: 999999, Anomalies: []Finding{{Kind: "dns-failure", Message: "y"}}}
	if Fingerprint(a, "warning") != Fingerprint(b, "warning") {
		t.Fatal("expected same incident fingerprint when only counters moved inside the same health bucket")
	}
	c := Snapshot{Mode: "enforce", HealthScore: 91, Anomalies: []Finding{{Kind: "dns-failure", Message: "x"}}}
	if Fingerprint(a, "warning") == Fingerprint(c, "warning") {
		t.Fatal("mode change must change fingerprint")
	}
}

func TestSuggestionsReactToSnapshot(t *testing.T) {
	s := Suggestions(Snapshot{AgentsTotal: 2, AgentsStale: 1, Mode: "enforce"})
	joined := ""
	for _, q := range s {
		joined += q
	}
	if !containsAny(joined, "stale", "lease") {
		t.Fatalf("suggestions=%v", s)
	}
}

func TestExplainQuestion(t *testing.T) {
	q := ExplainQuestion(ExplainRequest{Page: "drops", Kind: "kfree_skb", Subject: "node/a", Message: "high drop rate"})
	if q == "" || !containsAny(q, "drops", "kfree_skb") {
		t.Fatalf("q=%q", q)
	}
}
