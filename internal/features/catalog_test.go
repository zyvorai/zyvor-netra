// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package features

import "testing"

func TestCatalogIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Catalog() {
		if f.ID == "" || f.HelmSet == "" {
			t.Fatalf("incomplete feature: %+v", f)
		}
		if seen[f.ID] {
			t.Fatalf("duplicate id %s", f.ID)
		}
		seen[f.ID] = true
	}
}

func TestByID(t *testing.T) {
	if ByID("dns-detect") == nil {
		t.Fatal("expected dns-detect")
	}
	if ByID("nope") != nil {
		t.Fatal("expected nil")
	}
}

func TestHelmSetPair(t *testing.T) {
	s, err := HelmSetPair("dns-detect", true)
	if err != nil || s != "dnsdetect.enabled=true" {
		t.Fatalf("got %q err=%v", s, err)
	}
	s, err = HelmSetPair("tlsfp", false)
	if err != nil || s != "agent.tlsfp=off" {
		t.Fatalf("tlsfp off: %q err=%v", s, err)
	}
}

func TestEnvPatchValue(t *testing.T) {
	f := ByID("dns-detect")
	v, err := EnvPatchValue(*f, true)
	if err != nil || v != "true" {
		t.Fatalf("got %q err=%v", v, err)
	}
	v, err = EnvPatchValue(*ByID("tlsfp"), false)
	if err != nil || v != "off" {
		t.Fatalf("tlsfp off: %q err=%v", v, err)
	}
}
