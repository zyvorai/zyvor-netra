// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kmsg

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFilter(t *testing.T) {
	in := "systemd[1]: Started ssh\n" +
		"kernel: TCP: request_sock_TCP: Possible SYN flooding\n" +
		"kernel: token=abc in netdev line\n" +
		"kernel: IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready\n"
	got := Filter(in, 10)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Text == "" || got[1].Text == "" {
		t.Fatal(got)
	}
	for _, n := range got {
		if n.Text == "kernel: token=abc in netdev line" {
			t.Fatal("secret line kept")
		}
	}
}

func TestFilterTruncatesOnRuneBoundary(t *testing.T) {
	line := "oom-kill " + strings.Repeat("é", 200)
	notes := Filter(line, 5)
	if len(notes) != 1 || !utf8.ValidString(notes[0].Text) || len(notes[0].Text) > 180 {
		t.Fatalf("%#v", notes)
	}
}
