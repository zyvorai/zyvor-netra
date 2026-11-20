// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package webhook

import (
	"testing"
	"time"
)

func TestParseConfigs(t *testing.T) {
	raw := `[{"name":"slack","url":"https://hooks.example/x","minSeverity":"warning","timeout":"5s","maxAttempts":3},
	         {"name":"pd","url":"https://events.example/y","secret":"s3cret"}]`
	cfgs, err := ParseConfigs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("got %d configs, want 2", len(cfgs))
	}
	if cfgs[0].Name != "slack" || cfgs[0].URL != "https://hooks.example/x" || cfgs[0].MinSeverity != "warning" || cfgs[0].Timeout != 5*time.Second || cfgs[0].MaxAttempts != 3 {
		t.Fatalf("unexpected config[0]: %#v", cfgs[0])
	}
	if cfgs[1].Secret != "s3cret" {
		t.Fatalf("unexpected config[1]: %#v", cfgs[1])
	}
}

func TestParseConfigsRejectsBadTimeout(t *testing.T) {
	if _, err := ParseConfigs(`[{"name":"x","url":"http://y","timeout":"not-a-duration"}]`); err == nil {
		t.Fatal("want error for invalid timeout")
	}
}

func TestParseConfigsRejectsMalformedJSON(t *testing.T) {
	if _, err := ParseConfigs(`not json`); err == nil {
		t.Fatal("want error for malformed JSON")
	}
}

func TestParseConfigsEmptyArray(t *testing.T) {
	cfgs, err := ParseConfigs(`[]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 0 {
		t.Fatalf("got %d configs, want 0", len(cfgs))
	}
}
