// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dnsdetect

import (
	"fmt"
	"testing"
	"time"
)

func TestObserveTracksSnapshotCounters(t *testing.T) {
	d := New(DefaultConfig())
	base := time.Now()
	d.Observe(Query{Name: "example.com", RCode: RCodeNoError, Timestamp: base, Namespace: "ns", Pod: "p"})
	d.Observe(Query{Name: "example.com", RCode: RCodeNoError, Timestamp: base.Add(time.Second), Namespace: "ns", Pod: "p"})

	snap := d.Snapshot()
	if snap.QueriesSeen != 2 {
		t.Fatalf("QueriesSeen = %d, want 2", snap.QueriesSeen)
	}
	if snap.DomainsTracked != 1 {
		t.Fatalf("DomainsTracked = %d, want 1", snap.DomainsTracked)
	}
}

func TestObserveIgnoresEmptyNameOrZeroTimestamp(t *testing.T) {
	d := New(DefaultConfig())
	d.Observe(Query{Name: "", RCode: RCodeNoError, Timestamp: time.Now()})
	d.Observe(Query{Name: "example.com", RCode: RCodeNoError})
	if snap := d.Snapshot(); snap.QueriesSeen != 0 {
		t.Fatalf("QueriesSeen = %d, want 0 for invalid queries", snap.QueriesSeen)
	}
}

func TestNXDomainStormDetected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NXDomainMinCount = 5
	cfg.NXDomainRatio = 0.7
	d := New(cfg)
	base := time.Now()
	for i := 0; i < 10; i++ {
		d.Observe(Query{
			Name:      "flaky.example.com",
			RCode:     RCodeNXDomain,
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Namespace: "ns", Pod: "p",
		})
	}
	findings := d.Findings()
	found := false
	for _, f := range findings {
		if f.Type == FindingNXDomainStorm {
			found = true
			if f.Domain != "example.com" {
				t.Fatalf("Domain = %q, want example.com", f.Domain)
			}
		}
	}
	if !found {
		t.Fatalf("expected an nxdomain_storm finding, got %+v", findings)
	}
}

func TestServfailStormDetected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServfailMinCount = 5
	cfg.ServfailRatio = 0.7
	d := New(cfg)
	base := time.Now()
	for i := 0; i < 10; i++ {
		d.Observe(Query{
			Name:      "broken.example.org",
			RCode:     RCodeServFail,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingServfailStorm {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a servfail_storm finding")
	}
}

func TestBeaconingDetectedOnRegularInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BeaconMinSamples = 5
	cfg.BeaconMaxJitter = 500 * time.Millisecond
	d := New(cfg)
	base := time.Now()
	for i := 0; i < 8; i++ {
		d.Observe(Query{
			Name:      "beacon.example.net",
			RCode:     RCodeNoError,
			Timestamp: base.Add(time.Duration(i) * 30 * time.Second),
		})
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingBeaconing {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a beaconing finding for a fixed 30s cadence")
	}
}

func TestTunnelingDetectedOnHighEntropySubdomainVolume(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxUniqueSubdomains = 20
	cfg.MinAvgLabelLen = 15
	cfg.MinEntropy = 3.0
	cfg.MinQueryRate = 0
	d := New(cfg)
	base := time.Now()
	labels := []string{
		"a1b2c3d4e5f6a7b8", "q9w8e7r6t5y4u3i2", "z1x2c3v4b5n6m7a8",
		"k1l2j3h4g5f6d7s8", "p1o2i3u4y5t6r7e8", "m1n2b3v4c5x6z7a8",
		"h1g2f3d4s5a6q7w8", "t1r2e3w4q5a6z7x8", "u1i2o3p4l5k6j7h8",
		"c1v2b3n4m5a6s7d8", "f1g2h3j4k5l6z7x8", "w1e2r3t4y5u6i7o8",
		"n1m2b3v4c5x6z7a9", "y1u2i3o4p5a6s7d9", "l1k2j3h4g5f6d7s9",
		"x1c2v3b4n5m6a7s9", "q2w3e4r5t6y7u8i9", "a2s3d4f5g6h7j8k9",
		"z2x3c4v5b6n7m8a9", "p2o3i4u5y6t7r8e9", "b2n3m4a5s6d7f8g9",
		"j2k3l4h5g6f7d8s9",
	}
	for i, lbl := range labels {
		// "io" is a plain public-suffix TLD (not a private PSL wildcard
		// like "github.io"), so EffectiveTLDPlusOne collapses everything
		// under it to "tunnel.io" — "example" ends up as part of the
		// subdomain path, not the registered domain.
		name := fmt.Sprintf("%s.example.tunnel.io", lbl)
		d.Observe(Query{Name: name, QType: QTypeTXT, RCode: RCodeNoError, Timestamp: base.Add(time.Duration(i) * time.Millisecond)})
	}
	found := false
	for _, f := range d.Findings() {
		if f.Type == FindingTunneling {
			found = true
			if f.Domain != "tunnel.io" {
				t.Fatalf("Domain = %q, want tunnel.io", f.Domain)
			}
		}
	}
	if !found {
		t.Fatalf("expected a tunneling finding for %d high-entropy subdomains", len(labels))
	}
}

func TestFindingsRespectsTTLSweep(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NXDomainMinCount = 3
	cfg.NXDomainRatio = 0.5
	cfg.FindingsTTL = time.Millisecond
	d := New(cfg)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		d.Observe(Query{Name: "stale.example.com", RCode: RCodeNXDomain, Timestamp: base.Add(time.Duration(i) * time.Second)})
	}
	// Findings() filters by wall-clock time.Now(), so a finding whose
	// LastSeen is an hour in the past is already outside a 1ms TTL.
	if findings := d.Findings(); len(findings) != 0 {
		t.Fatalf("expected findings older than FindingsTTL to be filtered out, got %+v", findings)
	}
}

func TestFindingsAreDeepCopiedAndSafeToMutate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NXDomainMinCount = 3
	cfg.NXDomainRatio = 0.5
	d := New(cfg)
	base := time.Now()
	for i := 0; i < 5; i++ {
		d.Observe(Query{Name: "mutate.example.com", RCode: RCodeNXDomain, Timestamp: base.Add(time.Duration(i) * time.Second)})
	}
	findings := d.Findings()
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	findings[0].Signals[0] = "tampered"
	again := d.Findings()
	for _, f := range again {
		for _, s := range f.Signals {
			if s == "tampered" {
				t.Fatal("mutating a returned Finding's slice leaked into internal state")
			}
		}
	}
}

func TestSplitDomainUsesPublicSuffixList(t *testing.T) {
	cases := []struct{ name, wantReg, wantSub string }{
		{"a.b.example.com", "example.com", "a.b"},
		{"example.com", "example.com", ""},
		{"x.github.io", "x.github.io", ""},
		{"sub.x.github.io", "x.github.io", "sub"},
	}
	for _, tc := range cases {
		reg, sub := splitDomain(tc.name)
		if reg != tc.wantReg || sub != tc.wantSub {
			t.Errorf("splitDomain(%q) = (%q, %q), want (%q, %q)", tc.name, reg, sub, tc.wantReg, tc.wantSub)
		}
	}
}

func TestLRUEvictsOldestBeyondCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDomains = 2
	d := New(cfg)
	base := time.Now()
	// Distinct registered domains (not just distinct subdomains of one
	// registered domain) so each Observe creates a separate LRU entry.
	d.Observe(Query{Name: "one.com", RCode: RCodeNoError, Timestamp: base})
	d.Observe(Query{Name: "two.com", RCode: RCodeNoError, Timestamp: base})
	d.Observe(Query{Name: "three.com", RCode: RCodeNoError, Timestamp: base})
	if snap := d.Snapshot(); snap.DomainsTracked != 2 {
		t.Fatalf("DomainsTracked = %d, want 2 (capped)", snap.DomainsTracked)
	}
}

func TestCEFEscape(t *testing.T) {
	got := CEFEscape(`a\b|c=d` + "\n\r")
	want := `a\\b\|c\=d` + `\n\r`
	if got != want {
		t.Fatalf("CEFEscape = %q, want %q", got, want)
	}
}
