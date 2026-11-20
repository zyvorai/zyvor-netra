// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package tlsfp

import "testing"

func TestRiskBoardRareAndECH(t *testing.T) {
	d := NewDetector(64)
	d.Observe("n1", Fingerprint{JA3: "rare1", JA4: "t13i", SNI: ""})
	d.Observe("n1", Fingerprint{JA3: "ech1", JA4: "t13d", SNI: "a.example", ECH: true})
	for i := 0; i < 5; i++ {
		d.Observe("n1", Fingerprint{JA3: "common", JA4: "t13d", SNI: "b.example"})
	}
	board := d.Risk(50, 2)
	if board.UniqueJA3 != 3 {
		t.Fatalf("uniqueJa3=%d want 3", board.UniqueJA3)
	}
	if board.ECHSightings != 1 {
		t.Fatalf("echSightings=%d want 1", board.ECHSightings)
	}
	if board.Rare < 1 {
		t.Fatalf("rare=%d want >=1", board.Rare)
	}
	var sawECH, sawRare, sawMissingSNI bool
	for _, it := range board.Items {
		for _, r := range it.Reasons {
			switch r {
			case "ech-extension":
				sawECH = true
				if it.Severity != "high" {
					t.Errorf("ECH severity=%s want high", it.Severity)
				}
			case "rare-fingerprint":
				sawRare = true
			case "missing-sni":
				sawMissingSNI = true
			}
		}
	}
	if !sawECH || !sawRare || !sawMissingSNI {
		t.Fatalf("reasons missing: ech=%v rare=%v missingSNI=%v items=%+v", sawECH, sawRare, sawMissingSNI, board.Items)
	}
}

func TestRiskNilDetector(t *testing.T) {
	var d *Detector
	board := d.Risk(10, 2)
	if board.Note == "" || len(board.Items) != 0 {
		t.Fatalf("%+v", board)
	}
}
