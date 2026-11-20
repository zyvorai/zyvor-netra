// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/bpfattach"
	"github.com/zyvorai/netra/internal/models"
)

const (
	// bpfAttachEvery is how often the kernel is asked what is attached. It is a
	// few hundred syscalls on a node with many interfaces, so it runs well below
	// the 3 s report cadence.
	bpfAttachEvery = 30 * time.Second
	// bpfAttachRefresh re-sends an unchanged inventory this often so a controller
	// that restarted (and lost its copy) recovers without waiting for a change.
	bpfAttachRefresh = 5 * time.Minute
)

// startBPFAttach enables the read-only attachment inventory. NETRA_BPF_ATTACH=auto
// (default) or off. It needs no new privilege (the agent already holds
// CAP_BPF/CAP_NET_ADMIN) and changes nothing: it only asks the kernel what is
// attached, so the controller can tell when the hooks the agent believes it has
// are gone (docs/bpf-attachments.md).
func (a *Agent) startBPFAttach() {
	if strings.ToLower(env("NETRA_BPF_ATTACH", "auto")) == "off" {
		a.log.Info("BPF attachment inventory skipped by NETRA_BPF_ATTACH=off")
		return
	}
	if a.bpfSource == nil {
		a.bpfSource = bpfattach.NewSource()
	}
}

// readBPFAttach returns this tick's report and a commit function to call only
// after the controller accepted it. nil means the inventory is off.
func (a *Agent) readBPFAttach(now time.Time) (*models.BPFAttachReport, func()) {
	noop := func() {}
	if a.bpfSource == nil {
		return nil, noop
	}
	if a.bpfLastAt.IsZero() || now.Sub(a.bpfLastAt) >= bpfAttachEvery {
		a.bpfLast = bpfattach.Collect(a.bpfSource, now)
		a.bpfLastAt = now
	}
	rep := a.bpfLast
	if !rep.Available {
		return &rep, noop
	}
	if rep.Hash == a.bpfSentHash && now.Sub(a.bpfSentAt) < bpfAttachRefresh {
		// Same list as the controller already holds: send the summary only.
		stub := models.BPFAttachReport{
			Available: true, Unchanged: true, Hash: rep.Hash, ObservedAt: rep.ObservedAt,
			TCXSupported: rep.TCXSupported, Total: rep.Total, Truncated: rep.Truncated,
		}
		return &stub, noop
	}
	return &rep, func() { a.bpfSentHash, a.bpfSentAt = rep.Hash, now }
}
