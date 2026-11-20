// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import "testing"

func TestNetlinkPath(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"state"}, "/api/v1/netlink?view=state"},
		{[]string{"state", "--node", "worker-3"}, "/api/v1/netlink?node=worker-3&view=state"},
		{[]string{"events"}, "/api/v1/netlink?view=events"},
		{[]string{"events", "--kind", "route", "--node", "w 1", "--since", "30m", "--limit", "200"},
			"/api/v1/netlink?kind=route&limit=200&node=w+1&since=30m&view=events"},
		{[]string{"findings"}, "/api/v1/netlink/findings?"},
		{[]string{"findings", "--node", "worker-3", "--window", "1h"}, "/api/v1/netlink/findings?node=worker-3&window=1h"},
	}
	for _, c := range cases {
		got, err := netlinkPath(c.args)
		if err != nil || got != c.want {
			t.Errorf("%v: got %q, %v; want %q", c.args, got, err, c.want)
		}
	}
	for _, bad := range [][]string{
		nil, {"bogus"}, {"events", "--bogus", "x"}, {"events", "--kind"},
		{"state", "--since", "5m"}, {"state", "--kind", "route"}, {"state", "--window", "1h"},
		{"events", "--window", "1h"}, {"findings", "--kind", "route"}, {"findings", "--since", "5m"}, {"findings", "--limit", "5"},
	} {
		if got, err := netlinkPath(bad); err == nil {
			t.Errorf("%v: accepted, got %q", bad, got)
		}
	}
}
