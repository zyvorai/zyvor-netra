// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package tlsfp

import (
	"testing"
)

func TestParseClientHelloECH(t *testing.T) {
	data := buildClientHello(helloOpts{
		version: 0x0303,
		ciphers: []uint16{0x1301},
		sni:     "example.com",
		ech:     true,
	})
	fp, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if !fp.ECH {
		t.Fatal("expected ECH=true when ext 0xfe0d present")
	}
}

func TestDetectorLRUEviction(t *testing.T) {
	d := NewDetector(2)
	d.Observe("n1", Fingerprint{JA3: "aaa", JA4: "t12d"})
	d.Observe("n1", Fingerprint{JA3: "bbb", JA4: "t12d"})
	d.Observe("n1", Fingerprint{JA3: "ccc", JA4: "t12d"})
	snap := d.Snapshot(10)
	if len(snap) != 2 {
		t.Fatalf("len=%d want 2 after LRU eviction", len(snap))
	}
	for _, o := range snap {
		if o.JA3 == "aaa" {
			t.Fatal("oldest JA3 should have been evicted")
		}
	}
}

func TestDetectorStats(t *testing.T) {
	if NewDetector(0).Stats()["enabled"] != true {
		t.Fatal("expected enabled detector")
	}
	var nilDet *Detector
	st := nilDet.Stats()
	if st["enabled"] != false || st["uniqueJa3"] != 0 {
		t.Fatalf("nil detector stats = %#v", st)
	}
}
