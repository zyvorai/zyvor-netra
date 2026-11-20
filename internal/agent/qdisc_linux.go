// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package agent

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/zyvorai/netra/internal/models"
)

// readQdiscStats reads tc-qdisc drop/overlimit/requeue counters (equivalent
// to `tc -s qdisc show`) for every non-loopback interface, mirroring
// readNodeStack's interface enumeration (all host interfaces, not just the
// TC/TCX-attached subset in a.interfaces — qdisc drops can occur on any
// interface). Source is netlink, not a BPF map: no new map, no verifier
// involvement.
func (a *Agent) readQdiscStats() []models.QdiscStat {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []models.QdiscStat
	for _, it := range ifs {
		if it.Flags&net.FlagLoopback != 0 {
			continue
		}
		link, err := netlink.LinkByName(it.Name)
		if err != nil {
			continue
		}
		qdiscs, err := netlink.QdiscList(link)
		if err != nil {
			continue
		}
		out = append(out, qdiscStatsFromNetlink(it.Name, qdiscs)...)
	}
	return out
}
