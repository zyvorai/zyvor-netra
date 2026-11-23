// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package tlsposture

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestParseJA4(t *testing.T) {
	tests := []struct {
		in      string
		ok      bool
		version string
		sni     bool
		legacy  bool
		alpn    string
		proto   string
	}{
		{"t13d1516h2_8daaf6152771_b186095e22b6", true, "1.3", true, false, "h2", "tcp"},
		{"t12i0809http_x", false, "", false, false, "", ""}, // too long a first segment
		{"t12i080900_abc_def", true, "1.2", false, false, "", "tcp"},
		{"t11d0710h1_a_b", true, "1.1", true, true, "h1", "tcp"},
		{"t10d0505h1", true, "1.0", true, true, "h1", "tcp"},
		{"ts3d0403h1", true, "ssl3", true, true, "h1", "tcp"},
		{"q13d0310h3_a_b", true, "1.3", true, false, "h3", "quic"},
		{"dd1d0203h1", true, "dtls1.0", true, true, "h1", "dtls"},
		{"t00d0203h1", true, "unknown", true, false, "h1", "tcp"},
		{" t13d1516h2_a_b ", true, "1.3", true, false, "h2", "tcp"},
		{"", false, "", false, false, "", ""},
		{"_", false, "", false, false, "", ""},
		{"x13d1516h2", false, "", false, false, "", ""},
		{"t99d1516h2", false, "", false, false, "", ""},
		{"t13x1516h2", false, "", false, false, "", ""},
		{"t13dAB16h2", false, "", false, false, "", ""},
		{"t13d15-6h2", false, "", false, false, "", ""},
		{"t13d1516", false, "", false, false, "", ""},
		{strings.Repeat("t", 10000), false, "", false, false, "", ""},
		{"t13d1516h2\x00\x00", false, "", false, false, "", ""},
	}
	for _, tc := range tests {
		got, ok := ParseJA4(tc.in)
		if ok != tc.ok {
			t.Fatalf("%q: ok=%v want %v (%+v)", tc.in, ok, tc.ok, got)
		}
		if !ok {
			continue
		}
		if got.Version != tc.version || got.SNI != tc.sni || got.Legacy != tc.legacy || got.ALPN != tc.alpn || got.Proto != tc.proto {
			t.Fatalf("%q: %+v", tc.in, got)
		}
	}
}

func agent(node string, stale bool, fps ...models.TLSFingerprintStat) models.AgentStatus {
	var a models.AgentStatus
	a.Node, a.Stale, a.TLSFingerprints = node, stale, fps
	return a
}

func fp(ns, wl, sni, ja4 string, n uint64, ech bool) models.TLSFingerprintStat {
	return models.TLSFingerprintStat{JA3: "j", JA4: ja4, SNI: sni, Count: n, Namespace: ns, WorkloadName: wl, ECH: ech}
}

func TestBuildInventoryAndFindings(t *testing.T) {
	res := Build([]models.AgentStatus{
		agent("n1", false,
			fp("shop", "cart", "Pay.Example.com", "t10d0505h1_a_b", 4, false),
			fp("shop", "cart", "api.example.com", "t13d1516h2_a_b", 90, true),
			fp("shop", "old", "legacy.example.com", "ts3d0403h1_a_b", 2, false),
			fp("shop", "tls12", "x.example.com", "t12d1209h2_a_b", 6, false),
			fp("shop", "junk", "j.example.com", "garbage", 3, false),
			fp("shop", "quic", "q.example.com", "q13d0310h3_a_b", 5, false),
			fp("shop", "zero", "z.example.com", "t13d1516h2_a_b", 0, false), // count 0 counts as one
		),
		agent("n2", true, fp("shop", "stale", "s.example.com", "t10d0505h1_a_b", 1000, false)), // stale agent ignored
	})
	if res.Summary.Hellos != 4+90+2+6+3+5+1 {
		t.Fatalf("hellos %d", res.Summary.Hellos)
	}
	if res.Summary.LegacyHellos != 6 || res.Summary.Unparsed != 3 || res.Summary.ECH != 90 || res.Summary.QUIC != 5 {
		t.Fatalf("%+v", res.Summary)
	}
	if res.Summary.WorkloadsSeen != 6 {
		t.Fatalf("workloads %d", res.Summary.WorkloadsSeen)
	}
	if res.Summary.TLS13Percent < 85 || res.Summary.TLS13Percent > 95 {
		t.Fatalf("tls13 %v", res.Summary.TLS13Percent)
	}
	kinds := map[string]Finding{}
	for _, f := range res.Findings {
		kinds[f.Kind+"/"+f.Workload] = f
	}
	for _, want := range []string{"legacy-max-version/cart", "ssl-max-version/old", "tls12-max/tls12", "unparsed-fingerprint/junk"} {
		if _, ok := kinds[want]; !ok {
			t.Fatalf("missing finding %s in %v", want, kinds)
		}
	}
	if _, bad := kinds["tls12-max/cart"]; bad {
		t.Fatal("a workload that also offers 1.3 must not be flagged tls12-max")
	}
	if res.Findings[0].Severity != "high" {
		t.Fatalf("worst first: %+v", res.Findings[0])
	}
	if res.Rows[0].Workload != "old" && res.Rows[0].Workload != "cart" {
		t.Fatalf("rows with legacy clients sort first: %+v", res.Rows[0])
	}
	// SNI is lower-cased so the same host does not split rows.
	found := false
	for _, r := range res.Rows {
		if r.SNI == "pay.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("sni not normalised")
	}
	if len(res.Caveats) == 0 {
		t.Fatal("caveats missing")
	}
}

func TestBuildEmptyAndHostile(t *testing.T) {
	res := Build(nil)
	if res.Rows == nil || res.Findings == nil || res.Summary.Versions == nil {
		t.Fatal("empty result must serialise as empty collections")
	}
	long := strings.Repeat("a", 5000) + ".example.com"
	res = Build([]models.AgentStatus{agent("n", false, fp("ns", "w", long, "t13d1516h2_a_b", ^uint64(0)>>2, false))})
	if len(res.Rows[0].SNI) > 253 {
		t.Fatalf("sni length %d", len(res.Rows[0].SNI))
	}
}

func TestBuildCardinalityBounds(t *testing.T) {
	var fps []models.TLSFingerprintStat
	for i := 0; i < 30000; i++ {
		fps = append(fps, fp("ns", fmt.Sprintf("w%d", i), "h.example.com", "t10d0505h1_a_b", 1, false))
	}
	res := Build([]models.AgentStatus{agent("n", false, fps...)})
	if len(res.Rows) > MaxRows || len(res.Findings) > MaxFindings || !res.Truncated {
		t.Fatalf("rows=%d findings=%d truncated=%v", len(res.Rows), len(res.Findings), res.Truncated)
	}
	if res.Summary.Hellos != 30000 {
		t.Fatalf("every hello is still counted, got %d", res.Summary.Hellos)
	}
}
