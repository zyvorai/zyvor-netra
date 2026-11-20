// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package agent

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func TestQdiscStatsFromNetlink(t *testing.T) {
	q := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			Handle: netlink.MakeHandle(1, 0),
			Statistics: &netlink.QdiscStatistics{
				Queue: &netlink.GnetStatsQueue{Drops: 42, Overlimits: 3, Requeues: 1},
				Basic: &netlink.GnetStatsBasic{Bytes: 1000, Packets: 10},
			},
		},
		QdiscType: "fq_codel",
	}

	out := qdiscStatsFromNetlink("eth0", []netlink.Qdisc{q})

	if len(out) != 1 {
		t.Fatalf("expected 1 stat, got %d", len(out))
	}
	st := out[0]
	if st.Interface != "eth0" || st.Kind != "fq_codel" {
		t.Errorf("unexpected interface/kind: %+v", st)
	}
	if st.Drops != 42 || st.Overlimits != 3 || st.Requeues != 1 {
		t.Errorf("unexpected queue stats: %+v", st)
	}
	if st.Bytes != 1000 || st.Packets != 10 {
		t.Errorf("unexpected basic stats: %+v", st)
	}
}

func TestQdiscStatsFromNetlink_NilStatistics(t *testing.T) {
	q := &netlink.GenericQdisc{QdiscType: "noqueue"}
	out := qdiscStatsFromNetlink("lo", []netlink.Qdisc{q})
	if len(out) != 1 || out[0].Drops != 0 {
		t.Errorf("expected a zero-drop stat for a qdisc with no statistics, got %+v", out)
	}
}
