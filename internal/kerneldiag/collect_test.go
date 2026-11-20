// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kerneldiag

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectParsesTunablesAndCounters(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "proc/sys/net/core/rmem_max"), "212992\n")
	mustWrite(t, filepath.Join(root, "proc/net/snmp"), "Udp: InDatagrams NoPorts InErrors RcvbufErrors SndbufErrors\nUdp: 100 2 3 4 5\n")
	mustWrite(t, filepath.Join(root, "proc/net/netstat"), "TcpExt: ListenDrops TCPBacklogDrop Other\nTcpExt: 7 8 99\n")

	got := Collect(root)
	if len(got.Tunables) != 1 || got.Tunables[0].Name != "net.core.rmem_max" || got.Tunables[0].Value != "212992" {
		t.Fatalf("unexpected tunables: %#v", got.Tunables)
	}
	counters := map[string]uint64{}
	for _, c := range got.Counters {
		counters[c.Name] = c.Value
	}
	for name, want := range map[string]uint64{"Udp.RcvbufErrors": 4, "Udp.SndbufErrors": 5, "TcpExt.ListenDrops": 7, "TcpExt.TCPBacklogDrop": 8} {
		if counters[name] != want {
			t.Errorf("%s=%d, want %d", name, counters[name], want)
		}
	}
	if _, ok := counters["TcpExt.Other"]; ok {
		t.Fatal("unexpected unbounded counter was collected")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
