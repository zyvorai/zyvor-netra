//go:build !linux

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import "github.com/zyvorai/netra/internal/models"

func (a *Agent) applyExeHashGate(cfg models.EBPFFastPathConfig) error {
	return nil
}
