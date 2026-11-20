// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"github.com/vishvananda/netlink"

	"github.com/zyvorai/netra/internal/models"
)

// qdiscStatsFromNetlink converts the netlink library's Qdisc list into
// Netra's model shape. Split out from readQdiscStats (qdisc_linux.go) so the
// conversion is unit-testable without a live kernel/netlink socket, and
// buildable on any OS since it touches no OS-specific netlink calls.
func qdiscStatsFromNetlink(iface string, qdiscs []netlink.Qdisc) []models.QdiscStat {
	out := make([]models.QdiscStat, 0, len(qdiscs))
	for _, q := range qdiscs {
		attrs := q.Attrs()
		st := models.QdiscStat{
			Interface: iface,
			Kind:      q.Type(),
			Handle:    netlink.HandleStr(attrs.Handle),
		}
		if attrs.Statistics != nil {
			if attrs.Statistics.Queue != nil {
				st.Drops = uint64(attrs.Statistics.Queue.Drops)
				st.Overlimits = uint64(attrs.Statistics.Queue.Overlimits)
				st.Requeues = uint64(attrs.Statistics.Queue.Requeues)
			}
			if attrs.Statistics.Basic != nil {
				st.Bytes = attrs.Statistics.Basic.Bytes
				st.Packets = uint64(attrs.Statistics.Basic.Packets)
			}
		}
		out = append(out, st)
	}
	return out
}
