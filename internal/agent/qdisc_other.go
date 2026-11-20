// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package agent

import "github.com/zyvorai/netra/internal/models"

func (a *Agent) readQdiscStats() []models.QdiscStat { return nil }
