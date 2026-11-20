//go:build linux

package agent

import (
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/procmeta"
)

// procMetaCache is process-wide rather than a field on Agent: there is
// exactly one Agent per process (this is a long-running daemon, not a
// library used from multiple goroups with different configs), and keeping
// it here means agent.go — otherwise portable — never needs to reference a
// Linux-only type.
var procMetaCache = procmeta.NewCache(30*time.Second, 8192)

// readProcessMeta resolves /proc metadata for the given PIDs. A read
// failure for one PID (e.g. it has already exited) is recorded on that
// entry's AttributionError rather than dropping the entry or failing the
// whole report.
func (a *Agent) readProcessMeta(pids []uint32) []models.ProcessMetaStat {
	if !a.procMetaEnabled || len(pids) == 0 {
		return nil
	}
	out := make([]models.ProcessMetaStat, 0, len(pids))
	for _, pid := range pids {
		m, err := procMetaCache.Get(int(pid))
		if err != nil {
			out = append(out, models.ProcessMetaStat{PID: pid, AttributionError: err.Error()})
			continue
		}
		st := models.ProcessMetaStat{
			PID:              uint32(m.Identity.PID),
			StartTimeJiffies: m.Identity.StartTime,
			Comm:             m.Comm,
			PPID:             m.PPID,
			EffectiveUID:     m.Cred.EffUID,
			NoNewPrivs:       m.NoNewPrivs,
			SeccompMode:      m.Seccomp,
			LSMLabel:         m.LSMLabel,
			Exe:              m.Exe,
			ExeHash:          m.ExeHash,
			NetNS:            m.NetNS,
			CapEff:           m.Caps.Eff,
			CapNames:         m.Caps.NetworkRelevant(),
			ContainerPID:     m.ContainerPID(),
			KernelThread:     m.KernelThread,
			ProcessKind:      m.Kind.String(),
		}
		if m.Cgroup != nil {
			st.CgroupPath = m.Cgroup.Raw
			st.PodUID = m.Cgroup.PodUID
			st.ContainerID = m.Cgroup.ContainerID
			st.QoSClass = m.Cgroup.QoSClass
		}
		out = append(out, st)
	}
	return out
}

// sweepProcessMetaCache evicts expired process-metadata cache entries. It
// is a no-op (returns immediately) when procmeta was never enabled, so
// calling it unconditionally from the agent's ticker is cheap.
func sweepProcessMetaCache() {
	procMetaCache.Sweep()
}
