// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/nodeiso"
)

// TestNodeIsolationVethAttach attaches the real program to the TCX egress of
// a scratch veth whose peer lives in its own network namespace (in the
// spirit of FluxVM's scripts/test-ebpf-smoke.sh), sends genuine UDP through
// it, and checks shadow counts while enforce drops. It never touches a
// real interface.
func TestNodeIsolationVethAttach(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 not installed")
	}
	ns, host, peer := fmt.Sprintf("nisotest%d", os.Getpid()%10000), "niso0", "niso1"
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	_ = exec.Command("ip", "link", "del", host).Run()
	_ = exec.Command("ip", "netns", "del", ns).Run()
	run("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run("link", "add", host, "type", "veth", "peer", "name", peer)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", host).Run() })
	run("link", "set", peer, "netns", ns)
	// IPv6 MLD/RS packets the kernel sends on a fresh link would land in the
	// enforce counters (default deny) and make the totals racy.
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+host+"/disable_ipv6", []byte("1"), 0o644); err != nil {
		t.Logf("disable IPv6 on %s: %v", host, err)
	}
	run("addr", "add", "10.250.77.1/30", "dev", host)
	run("link", "set", host, "up")
	run("-n", ns, "addr", "add", "10.250.77.2/30", "dev", peer)
	run("-n", ns, "link", "set", peer, "up")

	iso, err := nodeiso.Load(nodeiso.Options{ObjectPath: testNodeIsoObjectPath(), Interfaces: []string{host}})
	if err != nil {
		t.Fatalf("load + attach: %v", err)
	}
	t.Cleanup(func() { _ = iso.Close() })
	if a := iso.Attached(); len(a) != 1 || a[0] != "nodeiso-tcx-egress:"+host {
		t.Fatalf("attached: %v", a)
	}

	send := func(port, n int) {
		t.Helper()
		// Unconnected, so the peer's ICMP port-unreachable cannot turn later
		// writes into ECONNREFUSED before they reach the egress hook.
		c, err := net.ListenPacket("udp4", "10.250.77.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		dst := &net.UDPAddr{IP: net.ParseIP("10.250.77.2"), Port: port}
		for range n {
			if _, err := c.WriteTo([]byte("netra-nodeiso"), dst); err != nil {
				t.Logf("send to %v: %v", dst, err)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	snap := func() *models.NodeIsolationStatus {
		t.Helper()
		st, err := iso.Snapshot(10)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	send(9, 2) // resolves ARP; no policy yet, nothing counted
	if st := snap(); st.Allowed+st.WouldBlock+st.Blocked != 0 {
		t.Fatalf("no policy must not evaluate: %+v", st)
	}

	spec := &models.NodeIsolationSpec{PolicyID: "veth", Revision: 1, Mode: models.NodeIsolationShadow,
		Rules: []models.NodeIsolationRule{{CIDR: "10.250.77.2/32", Protocol: "udp", PortFrom: 9, PortTo: 9}}}
	if err := iso.Apply(spec, nil, ""); err != nil {
		t.Fatal(err)
	}
	send(9, 3)
	send(10, 4)
	st := snap()
	if st.Allowed != 3 || st.WouldBlock != 4 || st.Blocked != 0 {
		t.Fatalf("shadow: %+v (want 3 allowed, 4 would-block, 0 blocked)", st)
	}
	if len(st.Top) != 1 || st.Top[0].Address != "10.250.77.2" || st.Top[0].Port != 10 || st.Top[0].Protocol != "udp" {
		t.Fatalf("top destinations: %+v", st.Top)
	}

	until := time.Now().Add(time.Minute)
	spec = &models.NodeIsolationSpec{PolicyID: "veth", Revision: 2, Mode: models.NodeIsolationEnforce, LeaseUntil: &until, Rules: spec.Rules}
	if err := iso.Apply(spec, nil, ""); err != nil {
		t.Fatal(err)
	}
	send(10, 5)
	send(9, 1)
	st = snap()
	if st.Blocked != 5 || st.Allowed != 4 || st.Mode != "enforce" {
		t.Fatalf("enforce: %+v (want 5 blocked, 4 allowed in total)", st)
	}
}
