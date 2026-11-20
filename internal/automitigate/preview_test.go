// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package automitigate

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/scandetect"
	"github.com/zyvorai/netra/internal/store"
)

func TestPreviewNeverMutatesAndListsCandidates(t *testing.T) {
	st := store.New()
	cfg := scandetect.DefaultConfig()
	cfg.Window = time.Minute
	cfg.MaxDestIPs = 2
	cfg.MinAttempts = 2
	scan := scandetect.New(cfg)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		scan.Observe(scandetect.Event{
			Timestamp: now, Namespace: "prod", Pod: "api", Node: "n1",
			DstIP: fmt.Sprintf("203.0.113.%d", i+1), DstPort: 443,
		})
	}
	eng := New(slog.Default(), st, scan, Config{
		Enabled: true, Interval: time.Minute, ConnRatePerSecond: 10,
		UDPPacketDelta: 1000, MaxActionsPerTick: 20,
	})
	before := st.Config().Revision
	res := eng.Preview(nil)
	if !res.Enabled {
		t.Fatal("expected enabled")
	}
	if res.Caveat == "" {
		t.Fatal("missing caveat")
	}
	if st.Config().Revision != before {
		t.Fatal("preview mutated store revision")
	}
	if len(scan.Findings()) == 0 {
		t.Fatal("expected scan findings to drive preview")
	}
	if len(res.Candidates) == 0 {
		t.Fatal("expected candidates")
	}
}
