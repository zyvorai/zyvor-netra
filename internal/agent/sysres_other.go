//go:build !linux

package agent

import "github.com/zyvorai/netra/internal/models"

// readNodeResources is a no-op on non-Linux: internal/sysres reads /proc
// and cgroup v2, which are Linux-only mechanisms. This stub exists
// purely so internal/agent keeps building and testing on a non-Linux
// development machine, matching readProcessMeta's split in
// procmeta_other.go.
func (a *Agent) readNodeResources() (models.NodeResourceSnapshot, models.HostProcessTops) {
	return models.NodeResourceSnapshot{}, models.HostProcessTops{}
}
