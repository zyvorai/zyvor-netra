// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package leaserails

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestDisabledAllowsEverything(t *testing.T) {
	d := Evaluate(Config{}, Request{Ops: []Op{{Seconds: 1 << 40, CatchAll: true, Protected: true}}, Resulting: make([]Held, 100000)})
	if !d.Allowed() || len(d.Waived) != 0 {
		t.Fatalf("%+v", d)
	}
}

func codes(d Decision) string {
	var c []string
	for _, t := range d.Trips {
		c = append(c, t.Code)
	}
	return strings.Join(c, ",")
}

func TestRails(t *testing.T) {
	op := func(s int64) Op { return Op{Rule: "r", Seconds: s} }
	cases := []struct {
		name string
		cfg  Config
		req  Request
		want string
	}{
		{"concurrent ok", Config{MaxConcurrent: 2}, Request{Resulting: make([]Held, 2)}, ""},
		{"concurrent trip", Config{MaxConcurrent: 2}, Request{Resulting: make([]Held, 3)}, CodeMaxConcurrent},
		{"duration trip", Config{MaxDuration: time.Hour}, Request{Ops: []Op{op(3601)}}, CodeMaxDuration},
		{"duration ok", Config{MaxDuration: time.Hour}, Request{Ops: []Op{op(3600)}}, ""},
		{"breadth v4", Config{MaxBreadthV4: 256}, Request{Resulting: []Held{{pfx("10.0.0.0/24")}, {pfx("10.0.1.0/30")}}}, CodeMaxBreadth},
		{"breadth v4 ok", Config{MaxBreadthV4: 512}, Request{Resulting: []Held{{pfx("10.0.0.0/24")}, {pfx("10.0.1.0/24")}}}, ""},
		{"breadth v6", Config{MaxBreadthV6: 4}, Request{Resulting: []Held{{pfx("2001:db8::/62")}, {pfx("2001:db8:1::/64")}}}, CodeMaxBreadth},
		{"breadth v6 huge", Config{MaxBreadthV6: 1 << 62}, Request{Resulting: []Held{{pfx("::/0")}}}, CodeMaxBreadth},
		{"rate trip", Config{RateCount: 3, RateWindow: time.Minute}, Request{Ops: []Op{op(60), op(60)}, ActorRecent: 2}, CodeActorRate},
		{"rate ok", Config{RateCount: 3, RateWindow: time.Minute}, Request{Ops: []Op{op(60)}, ActorRecent: 2}, ""},
		{"catch-all needs break-glass", Config{BreakGlass: true}, Request{Ops: []Op{{Rule: "x", Seconds: 60, CatchAll: true}}}, CodeCatchAll},
		{"protected needs break-glass", Config{BreakGlass: true}, Request{Ops: []Op{{Rule: "x", Seconds: 60, Protected: true}}}, CodeProtected},
		{"catch-all not gated when rail off", Config{MaxConcurrent: 5}, Request{Ops: []Op{{Seconds: 60, CatchAll: true}}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := codes(Evaluate(c.cfg, c.req)); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestBreakGlass(t *testing.T) {
	cfg := Config{BreakGlass: true, MaxDuration: time.Hour}
	ops := []Op{{Rule: "x", Seconds: 60, CatchAll: true}}
	d := Evaluate(cfg, Request{Ops: ops, BreakGlass: "incident 4711 approved"})
	if !d.Allowed() || !d.BreakGlass || len(d.Waived) != 1 {
		t.Fatalf("%+v", d)
	}
	d = Evaluate(cfg, Request{Ops: ops})
	if d.Allowed() || !d.NeedsBreakGlass {
		t.Fatalf("%+v", d)
	}
	for _, bad := range []string{"short", strings.Repeat("a", 201), "bad\x07reason here"} {
		d = Evaluate(cfg, Request{Ops: ops, BreakGlass: bad})
		if d.Allowed() || !strings.Contains(codes(d), CodeBreakGlass) {
			t.Fatalf("%q accepted: %+v", bad, d)
		}
	}
	// Break-glass never waives the hard rails.
	d = Evaluate(cfg, Request{Ops: []Op{{Rule: "x", Seconds: 7200, CatchAll: true}}, BreakGlass: "incident 4711 approved"})
	if d.Allowed() || !strings.Contains(codes(d), CodeMaxDuration) {
		t.Fatalf("%+v", d)
	}
}

func TestParseEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := ParseEnv(env(map[string]string{
		"NETRA_LEASE_MAX_CONCURRENT": "5", "NETRA_LEASE_MAX_DURATION": "2h", "NETRA_LEASE_MAX_BREADTH_V4": "1024",
		"NETRA_LEASE_MAX_BREADTH_V6": "8", "NETRA_LEASE_BREAK_GLASS_REQUIRED": "true", "NETRA_LEASE_ACTOR_RATE": "10/1m"}))
	if err != nil || c.MaxConcurrent != 5 || c.MaxDuration != 2*time.Hour || c.RateCount != 10 || !c.BreakGlass || !c.Enabled() {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := ParseEnv(env(nil)); err != nil || c.Enabled() {
		t.Fatalf("defaults must be off: %+v %v", c, err)
	}
	for k, v := range map[string]string{
		"NETRA_LEASE_MAX_CONCURRENT": "-1", "NETRA_LEASE_MAX_DURATION": "soon", "NETRA_LEASE_MAX_BREADTH_V4": "x",
		"NETRA_LEASE_BREAK_GLASS_REQUIRED": "maybe", "NETRA_LEASE_ACTOR_RATE": "10", "NETRA_LEASE_MAX_DURATION_": "",
	} {
		if v == "" {
			continue
		}
		if _, err := ParseEnv(env(map[string]string{k: v})); err == nil {
			t.Fatalf("%s=%s accepted", k, v)
		}
	}
	if _, err := ParseEnv(env(map[string]string{"NETRA_LEASE_ACTOR_RATE": "0/1m"})); err == nil {
		t.Fatal("zero rate accepted")
	}
}

func TestBreadthSaturates(t *testing.T) {
	v4, v6 := Breadth([]netip.Prefix{pfx("0.0.0.0/0"), pfx("0.0.0.0/0"), pfx("::/0"), pfx("::/0"), {}})
	if v4 != 1<<33 || v6 != ^uint64(0) {
		t.Fatalf("%d %d", v4, v6)
	}
}
