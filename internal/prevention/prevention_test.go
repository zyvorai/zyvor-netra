// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package prevention

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/intel"
)

func TestBuildGapsAndCoverage(t *testing.T) {
	s := Build(Input{GeneratedAt: time.Now().UTC(), Mode: "observe"})
	if s.Headline == "" || len(s.Gaps) == 0 {
		t.Fatalf("%+v", s)
	}
	until := time.Now().UTC().Add(time.Hour)
	s = Build(Input{
		GeneratedAt: time.Now().UTC(), Mode: "enforce", LeaseUntil: &until,
		IntelFeed:   []intel.Entry{{Type: "ip", Value: "203.0.113.1"}},
		BlockedIPv4: 1, TLSFPUnique: 2,
	})
	if !s.LeaseActive || s.IntelFeedEntries != 1 {
		t.Fatalf("%+v", s)
	}
}
