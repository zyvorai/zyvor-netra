// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/scandetect"
)

func warmStartDetectors(log *slog.Logger, stateFile string, dns *dnsdetect.Detector, dnsOn bool, scan *scandetect.Detector, scanOn bool) {
	if stateFile == "" {
		return
	}
	if dnsOn && dns != nil {
		n, err := dns.LoadPersist(stateFile + ".dnsdetect")
		if err != nil {
			log.Warn("dns-detect warm-start", "error", err)
		} else if n > 0 {
			log.Info("dns-detect warm-start", "findings", n)
		}
	}
	if scanOn && scan != nil {
		n, err := scan.LoadPersist(stateFile + ".scandetect")
		if err != nil {
			log.Warn("scan-detect warm-start", "error", err)
		} else if n > 0 {
			log.Info("scan-detect warm-start", "findings", n)
		}
	}
}

// startDetectorPersist periodically saves finding rings for HA continuity.
// Findings only — never auto-mitigate state. Returns a cancel func.
func startDetectorPersist(ctx context.Context, log *slog.Logger, stateFile string, dns *dnsdetect.Detector, dnsOn bool, scan *scandetect.Detector, scanOn bool, wg *sync.WaitGroup) context.CancelFunc {
	if stateFile == "" || (!dnsOn && !scanOn) {
		return nil
	}
	pctx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		save := func() {
			if dnsOn && dns != nil {
				if err := dns.SavePersist(stateFile + ".dnsdetect"); err != nil {
					log.Warn("dns-detect persist", "error", err)
				}
			}
			if scanOn && scan != nil {
				if err := scan.SavePersist(stateFile + ".scandetect"); err != nil {
					log.Warn("scan-detect persist", "error", err)
				}
			}
		}
		for {
			select {
			case <-pctx.Done():
				save()
				return
			case <-t.C:
				save()
			}
		}
	}()
	return cancel
}
