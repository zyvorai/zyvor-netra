//go:build !linux

package agent

import "github.com/zyvorai/netra/internal/models"

// applyCapabilityGate is a no-op on non-Linux, matching readProcessMeta's
// stub in procmeta_other.go: internal/procmeta is Linux-only (it reads
// /proc, which is the entire mechanism), and this agent's primary
// deployment target is Linux anyway. This stub exists purely so
// internal/agent keeps building and testing on a non-Linux development
// machine.
func (a *Agent) applyCapabilityGate(cfg models.EBPFFastPathConfig) error {
	return nil
}
