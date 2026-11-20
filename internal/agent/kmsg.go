// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"github.com/zyvorai/netra/internal/kmsg"
	"github.com/zyvorai/netra/internal/models"
)

func kernelNotes(node string) []models.KernelNote {
	raw := kmsg.Snapshot("/dev/kmsg")
	kept := kmsg.Filter(raw, 20)
	if len(kept) == 0 {
		return nil
	}
	out := make([]models.KernelNote, 0, len(kept))
	for _, n := range kept {
		out = append(out, models.KernelNote{Node: node, Text: n.Text})
	}
	return out
}
