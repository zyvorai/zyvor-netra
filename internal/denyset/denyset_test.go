// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package denyset

import (
	"strconv"
	"strings"
	"testing"
)

const good = `# comment
netra-denyset/1
name: inc-1
lease: 30m
deny cidr 203.0.113.9/24 egress   # masked
deny ip 198.51.100.7 both lease=5m
deny port tcp 445 ingress
`

func TestParseGood(t *testing.T) {
	f, errs := Parse([]byte(good))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if f.Name != "inc-1" || len(f.Rules) != 3 || f.LeaseSeconds != 1800 {
		t.Fatalf("%+v", f)
	}
	for _, r := range f.Rules {
		if r.LeaseSeconds == 0 {
			t.Fatalf("rule without lease %+v", r)
		}
		if r.CIDR == "203.0.113.0/24" && r.LeaseSeconds != 1800 {
			t.Fatal("default lease not applied")
		}
		if r.CIDR == "198.51.100.7/32" && r.LeaseSeconds != 300 {
			t.Fatal("rule lease not applied")
		}
	}
}

func TestParseErrors(t *testing.T) {
	hdr := "netra-denyset/1\nname: a\nlease: 10m\n"
	cases := []struct {
		name, in string
		line     int
		msg      string
	}{
		{"no header", "name: a\n", 1, "first line"},
		{"bad version", "netra-denyset/2\n", 1, "first line"},
		{"empty", "", 1, "missing"},
		{"missing lease", "netra-denyset/1\nname: a\n", 1, "lease: is required"},
		{"missing name", "netra-denyset/1\nlease: 5m\n", 1, "name: is required"},
		{"bad name", "netra-denyset/1\nname: A_B\nlease: 5m\n", 2, "name must"},
		{"dup name", hdr + "name: b\n", 4, "duplicate name"},
		{"lease too short", "netra-denyset/1\nname: a\nlease: 5s\n", 3, "between"},
		{"lease too long", "netra-denyset/1\nname: a\nlease: 48h\n", 3, "between"},
		{"lease junk", "netra-denyset/1\nname: a\nlease: forever\n", 3, "not a duration"},
		{"unknown directive", hdr + "allow cidr 1.1.1.0/24 egress\n", 4, "unknown directive"},
		{"bad cidr", hdr + "deny cidr 999.1.1.0/24 egress\n", 4, "invalid CIDR"},
		{"bad ip zone", hdr + "deny ip fe80::1%eth0 egress\n", 4, "invalid IP"},
		{"no direction", hdr + "deny cidr 10.0.0.0/8\n", 4, "usage"},
		{"bad direction", hdr + "deny cidr 10.0.0.0/8 sideways\n", 4, "direction"},
		{"port zero", hdr + "deny port tcp 0 egress\n", 4, "port must"},
		{"port big", hdr + "deny port tcp 70000 egress\n", 4, "port must"},
		{"bad proto", hdr + "deny port icmp 5 egress\n", 4, "protocol"},
		{"unknown opt", hdr + "deny cidr 10.0.0.0/8 egress forever=1\n", 4, "unknown option"},
		{"bad opt lease", hdr + "deny cidr 10.0.0.0/8 egress lease=0s\n", 4, "between"},
		{"permanent attempt", hdr + "deny cidr 10.0.0.0/8 egress lease=0\n", 4, "lease"},
		{"dup rule", hdr + "deny cidr 10.0.0.0/8 egress\ndeny cidr 10.1.2.3/8 egress\n", 5, "duplicate of the rule on line 4"},
		{"control char", hdr + "deny cidr 10.0.0.0/8 egress\x00\n", 4, "control"},
		{"long line", hdr + "deny " + strings.Repeat("a", 600) + "\n", 4, "limit"},
		{"unknown kind", hdr + "deny dns evil.example egress\n", 4, "unknown deny kind"},
		{"bare deny", hdr + "deny\n", 4, "needs a kind"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, errs := Parse([]byte(c.in))
			if f != nil || len(errs) == 0 {
				t.Fatalf("expected errors, got %+v", f)
			}
			found := false
			for _, e := range errs {
				if strings.Contains(e.Message, c.msg) && (c.line == 0 || e.Line == c.line) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want line %d %q in %v", c.line, c.msg, errs)
			}
		})
	}
}

func TestParseBounds(t *testing.T) {
	if _, errs := Parse(make([]byte, MaxFileBytes+1)); len(errs) != 1 {
		t.Fatal("oversize file accepted")
	}
	if _, errs := Parse([]byte("netra-denyset/1\n\xff\xfe\n")); len(errs) != 1 || !strings.Contains(errs[0].Message, "UTF-8") {
		t.Fatal(errs)
	}
	var b strings.Builder
	b.WriteString("netra-denyset/1\nname: a\nlease: 5m\n")
	for i := 0; i < MaxRules+5; i++ {
		b.WriteString("deny ip 10.0." + itoa(i/250) + "." + itoa(i%250) + " egress\n")
	}
	_, errs := Parse([]byte(b.String()))
	if len(errs) == 0 || len(errs) > MaxErrors {
		t.Fatalf("errors %d", len(errs))
	}
	var many strings.Builder
	many.WriteString("netra-denyset/1\nname: a\nlease: 5m\n")
	for i := 0; i < 300; i++ {
		many.WriteString("bogus\n")
	}
	_, errs = Parse([]byte(many.String()))
	if len(errs) != MaxErrors {
		t.Fatalf("errors not capped: %d", len(errs))
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestDiffAndHash(t *testing.T) {
	f, errs := Parse([]byte(good))
	if errs != nil {
		t.Fatal(errs)
	}
	leases := []Lease{
		{Owner: "inc-1", Type: "cidr", Key: "egress|203.0.113.0/24", Summary: "x", LeaseSeconds: 1800}, // unchanged
		{Owner: "inc-1", Type: "cidr", Key: "both|198.51.100.7/32", Summary: "y", LeaseSeconds: 60},    // extend
		{Owner: "inc-1", Type: "cidr", Key: "egress|192.0.2.0/24", Summary: "z", LeaseSeconds: 60},     // remove
		{Owner: "other", Type: "cidr", Key: "egress|192.0.2.128/25", Summary: "o", LeaseSeconds: 60},   // never removed
	}
	present := map[string]bool{"cidr|egress|203.0.113.0/24": true, "cidr|both|198.51.100.7/32": true, "cidr|egress|192.0.2.0/24": true, "cidr|egress|192.0.2.128/25": true, "port|ingress|TCP|445": true}
	items := Diff(f, leases, present)
	got := map[string]string{}
	for _, it := range items {
		got[it.Key] = it.Action
	}
	want := map[string]string{
		"egress|203.0.113.0/24": ActionUnchanged, "both|198.51.100.7/32": ActionExtend,
		"egress|192.0.2.0/24": ActionRemove, "ingress|TCP|445": ActionSkip,
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %s want %s", k, got[k], v)
		}
	}
	if _, ok := got["egress|192.0.2.128/25"]; ok {
		t.Fatal("another owner's lease appeared in plan")
	}
	h1 := Hash(f.Name, items)
	// Shuffle line numbers/comments: hash must not change.
	f2, _ := Parse([]byte(strings.ReplaceAll(good, "# comment", "\n\n# other")))
	if h2 := Hash(f2.Name, Diff(f2, leases, present)); h1 != h2 {
		t.Fatal("hash depends on layout")
	}
	f3, _ := Parse([]byte(strings.Replace(good, "lease: 30m", "lease: 31m", 1)))
	if Hash(f3.Name, Diff(f3, leases, present)) == h1 {
		t.Fatal("hash ignores lease change")
	}
	c := Counts(items)
	if c[ActionRemove] != 1 || c[ActionExtend] != 1 || c[ActionUnchanged] != 1 || c[ActionSkip] != 1 {
		t.Fatalf("%v", c)
	}
}

func TestEmptyFileRemovesOnlyOwned(t *testing.T) {
	f, errs := Parse([]byte("netra-denyset/1\nname: a\nlease: 5m\n"))
	if errs != nil {
		t.Fatal(errs)
	}
	items := Diff(f, []Lease{{Owner: "a", Type: "cidr", Key: "egress|1.0.0.0/8"}, {Owner: "b", Type: "cidr", Key: "egress|2.0.0.0/8"}}, map[string]bool{})
	if len(items) != 1 || items[0].Action != ActionRemove || items[0].Key != "egress|1.0.0.0/8" {
		t.Fatalf("%+v", items)
	}
}
