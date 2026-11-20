// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package agent

import (
	"context"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/netlinkwatch"
)

// startNetlink enables the read-only RTNL change recorder. NETRA_NETLINK=auto
// (default) or off. It needs no BPF and no privilege beyond the host network
// namespace, so there is no "required": a fault is reported in the report, and
// a platform without netlink is reported as Unavailable.
func (a *Agent) startNetlink(ctx context.Context) {
	if strings.ToLower(env("NETRA_NETLINK", "auto")) == "off" {
		a.log.Info("netlink change recorder skipped by NETRA_NETLINK=off")
		return
	}
	w, err := netlinkwatch.Start(ctx, netlinkEventBuffer())
	if err != nil {
		a.netlinkWhy = err.Error()
		if len(a.netlinkWhy) > maxWhy {
			a.netlinkWhy = a.netlinkWhy[:maxWhy]
		}
		a.log.Warn("netlink change recorder unavailable", "error", err)
		return
	}
	a.netlinkWatch = w
}

// netlinkEventBuffer is NETRA_NETLINK_EVENT_BUFFER, the agent-side ring size.
// A value that is not a positive integer falls back to the default; an absurd
// one is clamped by the watcher.
func netlinkEventBuffer() int {
	n, err := strconv.Atoi(env("NETRA_NETLINK_EVENT_BUFFER", ""))
	if err != nil || n <= 0 {
		return netlinkwatch.DefaultCapacity
	}
	return n
}

// readNetlink returns the recorder's report and a commit function. nil means
// the recorder is off; Unavailable means it could not start. The caller must
// call commit only after the controller accepted the report, so a failed POST
// resends the same events instead of dropping them.
func (a *Agent) readNetlink() (*models.NetlinkReport, func()) {
	noop := func() {}
	if a.netlinkWatch == nil {
		if a.netlinkWhy != "" {
			return &models.NetlinkReport{Unavailable: a.netlinkWhy}, noop
		}
		return nil, noop
	}
	rep := a.netlinkWatch.Report(netlinkwatch.MaxReportEvents)
	return &rep, func() { a.netlinkWatch.Commit(rep) }
}
