// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package intel

import (
	"strings"
	"testing"
)

func TestParseJSONWrapper(t *testing.T) {
	p, err := Parse(`{"entries":[{"type":"ip","value":"203.0.113.8","direction":"egress"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count != 1 || p.Entries[0].Type != "ip" {
		t.Fatalf("%#v", p)
	}
}

func TestParseCSVAndComments(t *testing.T) {
	raw := "# threat feed\n" +
		"ip,198.51.100.2,both\n" +
		"cidr,10.0.0.0/8,ingress\n" +
		"dns,malware.example,egress\n" +
		"sni,bad.example.com\n" +
		"nope this is junk\n"
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count != 4 {
		t.Fatalf("count=%d skipped=%#v", p.Count, p.Skipped)
	}
	if p.Dropped == 0 {
		t.Fatal("expected the junk line to be skipped")
	}
}

func TestParseBareTokens(t *testing.T) {
	p, err := Parse("203.0.113.9\n2001:db8::1\n203.0.113.0/24\nphish.example.org\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Count != 4 {
		t.Fatalf("%#v", p)
	}
	types := map[string]int{}
	for _, e := range p.Entries {
		types[e.Type]++
		if e.Direction != "egress" {
			t.Fatalf("bare token default direction: %#v", e)
		}
	}
	if types["ip"] != 2 || types["cidr"] != 1 || types["dns"] != 1 {
		t.Fatalf("types=%v", types)
	}
}

func TestParseRejectsEmptyAndDuplicates(t *testing.T) {
	if _, err := Parse("   "); err == nil {
		t.Fatal("empty")
	}
	p, err := Parse("203.0.113.9\n203.0.113.9\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Count != 1 || p.Dropped != 1 {
		t.Fatalf("%#v", p)
	}
	if !strings.Contains(p.Skipped[0].Message, "duplicate") {
		t.Fatalf("skip: %#v", p.Skipped)
	}
}

func TestNormalizeAliases(t *testing.T) {
	p, err := Parse(`[{"type":"fqdn","value":"a.example","direction":"EGRESS"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count != 1 || p.Entries[0].Type != "dns" || p.Entries[0].Direction != "egress" {
		t.Fatalf("%#v", p)
	}
}
