// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysctlaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestCollectGlobalAndPerInterfaceTunables(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv4/tcp_syncookies"), "1\n")
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv4/conf/eth0/rp_filter"), "0\n")
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv4/conf/all/rp_filter"), "1\n")
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv6/conf/eth0/disable_ipv6"), "0\n")
	// VLAN sub-interfaces contain a literal dot in their name — the path
	// must not be built by naively splitting on "." after joining.
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv4/conf/eth0.100/rp_filter"), "2\n")

	got := Collect(root)

	byKey := map[[2]string]models.SysctlAuditEntry{}
	for _, e := range got.Entries {
		byKey[[2]string{e.Name, e.Interface}] = e
	}

	global, ok := byKey[[2]string{"net.ipv4.tcp_syncookies", ""}]
	if !ok || global.Value != "1" || global.Category != CategorySecurity {
		t.Fatalf("expected global tcp_syncookies entry, got %#v (ok=%v)", global, ok)
	}

	eth0, ok := byKey[[2]string{"net.ipv4.conf.eth0.rp_filter", "eth0"}]
	if !ok || eth0.Value != "0" || eth0.Category != CategorySecurity {
		t.Fatalf("expected eth0 rp_filter entry, got %#v (ok=%v)", eth0, ok)
	}

	vlan, ok := byKey[[2]string{"net.ipv4.conf.eth0.100.rp_filter", "eth0.100"}]
	if !ok || vlan.Value != "2" {
		t.Fatalf("expected eth0.100 (VLAN) rp_filter entry to be read as one interface, got %#v (ok=%v)", vlan, ok)
	}

	v6, ok := byKey[[2]string{"net.ipv6.conf.eth0.disable_ipv6", "eth0"}]
	if !ok || v6.Value != "0" || v6.Category != CategoryIPv6 {
		t.Fatalf("expected eth0 disable_ipv6 entry, got %#v (ok=%v)", v6, ok)
	}
}

func TestCollectOmitsMissingFiles(t *testing.T) {
	root := t.TempDir()
	// Nothing written at all: every global/per-interface path is absent.
	got := Collect(root)
	if len(got.Entries) != 0 {
		t.Fatalf("expected no entries on an empty root, got %d", len(got.Entries))
	}
}

func TestCollectUnionsIPv4AndIPv6InterfaceLists(t *testing.T) {
	root := t.TempDir()
	// eth0 only has an ipv4 conf directory; eth1 only has ipv6.
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv4/conf/eth0/rp_filter"), "1\n")
	mustWrite(t, filepath.Join(root, "proc/sys/net/ipv6/conf/eth1/disable_ipv6"), "1\n")

	got := Collect(root)
	var sawEth0Security, sawEth1IPv6 bool
	for _, e := range got.Entries {
		if e.Interface == "eth0" && e.Category == CategorySecurity {
			sawEth0Security = true
		}
		if e.Interface == "eth1" && e.Category == CategoryIPv6 {
			sawEth1IPv6 = true
		}
	}
	if !sawEth0Security || !sawEth1IPv6 {
		t.Fatalf("expected both ipv4-only and ipv6-only interfaces to be covered, got entries: %#v", got.Entries)
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
