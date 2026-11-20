//go:build !linux

package agent

import "github.com/zyvorai/netra/internal/models"

// readProcessMeta is a no-op on non-Linux: internal/procmeta is Linux-only
// (it reads /proc, which is the entire mechanism), and this agent's
// primary deployment target is Linux anyway. This stub exists purely so
// internal/agent keeps building and testing on a non-Linux development
// machine.
func (a *Agent) readProcessMeta(pids []uint32) []models.ProcessMetaStat {
	return nil
}

func sweepProcessMetaCache() {}
