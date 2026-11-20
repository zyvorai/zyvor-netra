// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package agent

import (
	"github.com/zyvorai/netra/internal/models"
)

// enrichSocketOwnership binds live /proc identity onto TCP health rows.
// When the eBPF-attributed PID is gone or reused (procmeta read fails), the
// PID/comm fields are cleared and OwnershipStale is set so Drop Detective
// and the UI do not treat a recycled PID as the socket owner.
//
// When procmeta is disabled this is a no-op — the BPF cookie→pid join
// remains as before.
func (a *Agent) enrichSocketOwnership(tcp []models.TCPHealthStat, meta []models.ProcessMetaStat) {
	if !a.procMetaEnabled || len(tcp) == 0 {
		return
	}
	byPID := map[uint32]models.ProcessMetaStat{}
	for _, m := range meta {
		byPID[m.PID] = m
	}
	for i := range tcp {
		st := &tcp[i]
		if st.PID == 0 {
			continue
		}
		m, ok := byPID[st.PID]
		if !ok || m.AttributionError != "" {
			st.OwnershipStale = true
			st.PID = 0
			st.Comm = ""
			st.UID = 0
			continue
		}
		st.StartTimeJiffies = m.StartTimeJiffies
		st.Exe = m.Exe
		if m.Comm != "" {
			st.Comm = m.Comm
		}
	}
}

// watchCapChanges compares CapEff for currently owned socket processes
// against the previous sync cycle. Emits observe-only events when
// network-relevant capabilities change on a live process identity
// (pid+startTime). No new BPF; gated by procmeta.
//
// pidCgroup is built by the caller from the same tcpHealth slice meta's
// PIDs were sourced from (pidsFromTCPHealth) — every PID watchCapChanges
// considers owns a Netra-tracked TCP socket by construction, so its
// CgroupID is already known from that same sync cycle without a second
// lookup mechanism.
func (a *Agent) watchCapChanges(meta []models.ProcessMetaStat, pidCgroup map[uint32]uint64) []models.CapChangeEvent {
	if !a.procMetaEnabled || len(meta) == 0 {
		return nil
	}
	if a.prevCaps == nil {
		a.prevCaps = map[uint64]uint64{}
	}
	var out []models.CapChangeEvent
	seen := map[uint64]struct{}{}
	for _, m := range meta {
		if m.AttributionError != "" || m.PID == 0 {
			continue
		}
		key := uint64(m.PID)<<32 ^ m.StartTimeJiffies
		seen[key] = struct{}{}
		prev, ok := a.prevCaps[key]
		a.prevCaps[key] = m.CapEff
		if !ok || prev == m.CapEff {
			continue
		}
		ev := models.CapChangeEvent{
			PID:              m.PID,
			StartTimeJiffies: m.StartTimeJiffies,
			Comm:             m.Comm,
			Exe:              m.Exe,
			PreviousCapEff:   prev,
			CurrentCapEff:    m.CapEff,
			CgroupID:         pidCgroup[m.PID],
		}
		if ev.CgroupID != 0 {
			if w, ok := a.workloadIdentity(ev.CgroupID); ok {
				ev.Namespace, ev.Pod, ev.WorkloadKind, ev.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
			}
		}
		out = append(out, ev)
	}
	// Drop identities no longer in the report so the map cannot grow unboundedly.
	for k := range a.prevCaps {
		if _, ok := seen[k]; !ok {
			delete(a.prevCaps, k)
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// watchNamespaceChanges compares each process's network-namespace inode
// (procmeta.Meta.NetNS) against the previous sync cycle, exactly
// mirroring watchCapChanges' identity/dedup/pruning/cap shape. A live
// process moving network namespaces after start (setns(2)) is a
// container-escape or cross-namespace-debugging signal CapEff alone
// would not catch. No new BPF; gated by procmeta.
func (a *Agent) watchNamespaceChanges(meta []models.ProcessMetaStat, pidCgroup map[uint32]uint64) []models.NamespaceChangeEvent {
	if !a.procMetaEnabled || len(meta) == 0 {
		return nil
	}
	if a.prevNetNS == nil {
		a.prevNetNS = map[uint64]uint64{}
	}
	var out []models.NamespaceChangeEvent
	seen := map[uint64]struct{}{}
	for _, m := range meta {
		if m.AttributionError != "" || m.PID == 0 || m.NetNS == 0 {
			continue
		}
		key := uint64(m.PID)<<32 ^ m.StartTimeJiffies
		seen[key] = struct{}{}
		prev, ok := a.prevNetNS[key]
		a.prevNetNS[key] = m.NetNS
		if !ok || prev == m.NetNS {
			continue
		}
		ev := models.NamespaceChangeEvent{
			PID:              m.PID,
			StartTimeJiffies: m.StartTimeJiffies,
			Comm:             m.Comm,
			Exe:              m.Exe,
			PreviousNetNS:    prev,
			CurrentNetNS:     m.NetNS,
			CgroupID:         pidCgroup[m.PID],
		}
		if ev.CgroupID != 0 {
			if w, ok := a.workloadIdentity(ev.CgroupID); ok {
				ev.Namespace, ev.Pod, ev.WorkloadKind, ev.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
			}
		}
		out = append(out, ev)
	}
	// Drop identities no longer in the report so the map cannot grow unboundedly.
	for k := range a.prevNetNS {
		if _, ok := seen[k]; !ok {
			delete(a.prevNetNS, k)
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// watchExeHashChanges compares each process's on-disk executable
// content hash (procmeta.Meta.ExeHash) against the previous sync
// cycle, mirroring watchCapChanges/watchNamespaceChanges' identity/
// dedup/pruning/cap shape exactly. A live process's backing binary
// changing on disk is the observe-only half of the "Exe-hash leased
// deny" backlog item — no enforcement here, and no new BPF; gated by
// procmeta.
func (a *Agent) watchExeHashChanges(meta []models.ProcessMetaStat, pidCgroup map[uint32]uint64) []models.ExeHashChangeEvent {
	if !a.procMetaEnabled || len(meta) == 0 {
		return nil
	}
	if a.prevExeHash == nil {
		a.prevExeHash = map[uint64]string{}
	}
	var out []models.ExeHashChangeEvent
	seen := map[uint64]struct{}{}
	for _, m := range meta {
		if m.AttributionError != "" || m.PID == 0 || m.ExeHash == "" {
			continue
		}
		key := uint64(m.PID)<<32 ^ m.StartTimeJiffies
		seen[key] = struct{}{}
		prev, ok := a.prevExeHash[key]
		a.prevExeHash[key] = m.ExeHash
		if !ok || prev == m.ExeHash {
			continue
		}
		ev := models.ExeHashChangeEvent{
			PID:              m.PID,
			StartTimeJiffies: m.StartTimeJiffies,
			Comm:             m.Comm,
			Exe:              m.Exe,
			PreviousExeHash:  prev,
			CurrentExeHash:   m.ExeHash,
			CgroupID:         pidCgroup[m.PID],
		}
		if ev.CgroupID != 0 {
			if w, ok := a.workloadIdentity(ev.CgroupID); ok {
				ev.Namespace, ev.Pod, ev.WorkloadKind, ev.WorkloadName = w.Namespace, w.Pod, w.WorkloadKind, w.WorkloadName
			}
		}
		out = append(out, ev)
	}
	// Drop identities no longer in the report so the map cannot grow unboundedly.
	for k := range a.prevExeHash {
		if _, ok := seen[k]; !ok {
			delete(a.prevExeHash, k)
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
