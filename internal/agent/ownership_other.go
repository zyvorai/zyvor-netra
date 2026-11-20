// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package agent

import "github.com/zyvorai/netra/internal/models"

func (a *Agent) enrichSocketOwnership(_ []models.TCPHealthStat, _ []models.ProcessMetaStat) {}

func (a *Agent) watchCapChanges(_ []models.ProcessMetaStat, _ map[uint32]uint64) []models.CapChangeEvent {
	return nil
}

func (a *Agent) watchNamespaceChanges(_ []models.ProcessMetaStat, _ map[uint32]uint64) []models.NamespaceChangeEvent {
	return nil
}

func (a *Agent) watchExeHashChanges(_ []models.ProcessMetaStat, _ map[uint32]uint64) []models.ExeHashChangeEvent {
	return nil
}
