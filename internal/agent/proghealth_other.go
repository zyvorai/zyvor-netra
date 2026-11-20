// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package agent

import (
	"github.com/zyvorai/netra/internal/histograms"
	"github.com/zyvorai/netra/internal/models"
)

func (a *Agent) enableProgStats() {}

func (a *Agent) readProgramHealth() []models.BPFProgramStat { return nil }

func (a *Agent) readHostHistogramCounters() histograms.HostCounters {
	return histograms.HostCounters{}
}

func (a *Agent) markAttached(prog string) {
	if a.attachedProgs == nil {
		a.attachedProgs = map[string]bool{}
	}
	a.attachedProgs[prog] = true
}
