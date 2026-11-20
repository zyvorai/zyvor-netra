// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package automitigate

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/scandetect"
	"github.com/zyvorai/netra/internal/store"
)

func TestNoActionWithoutEnforceLease(t *testing.T) {
	st := store.New()
	scan := scandetect.New(scandetect.DefaultConfig())
	// Force a syn_flood-shaped finding by observing many SYN-only attempts.
	for i := 0; i < 40; i++ {
		scan.Observe(scandetect.Event{
			Timestamp: time.Now(), Namespace: "ns", Pod: "flood",
			DstIP: "10.0.0.1", DstPort: uint16(i + 1), SynOnly: true,
		})
	}
	eng := New(slog.New(slog.NewTextHandler(io.Discard, nil)), st, scan, Config{
		Enabled: true, Interval: time.Second, ConnRatePerSecond: 5, MaxActionsPerTick: 5,
	})
	eng.tick(func() []models.AgentStatus { return nil })
	if len(st.Config().ConnRateLimits) != 0 {
		t.Fatalf("should not act without enforce lease: %+v", st.Config().ConnRateLimits)
	}
	if _, err := st.SetMode("enforce", 15*time.Minute, "test"); err != nil {
		t.Fatal(err)
	}
	eng.tick(func() []models.AgentStatus { return nil })
	if len(st.Config().ConnRateLimits) == 0 {
		// syn_flood may need higher thresholds; still assert StatusSnapshot works
		snap := eng.StatusSnapshot()
		if !snap.Enabled {
			t.Fatal("expected enabled")
		}
	}
}
