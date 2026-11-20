// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// testTLSFPObjectPath defaults to the CI ebpf job output for netra_tlsfp.o.
func testTLSFPObjectPath() string {
	if p := os.Getenv("NETRA_BPF_TLSFP_TEST_OBJECT"); p != "" {
		return p
	}
	if _, err := os.Stat("/tmp/netra_tlsfp.o"); err == nil {
		return "/tmp/netra_tlsfp.o"
	}
	return filepath.Join(filepath.Dir(testObjectPath()), "netra_tlsfp.o")
}

func buildIPv4TCPWithPayload(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags byte, payload []byte) []byte {
	buf := make([]byte, ipHdrLen+tcpHdrLen+len(payload))
	writeIPv4TCP(buf, srcIP, dstIP, srcPort, dstPort, flags)
	binary.BigEndian.PutUint16(buf[2:4], uint16(ipHdrLen+tcpHdrLen+len(payload)))
	copy(buf[ipHdrLen+tcpHdrLen:], payload)
	return buf
}

func minimalClientHello() []byte {
	hello := make([]byte, 64)
	hello[0] = 0x16
	hello[1], hello[2] = 0x03, 0x01
	hello[3], hello[4] = 0x00, 0x3a
	hello[5] = 0x01
	return hello
}

func loadTLSFP(t *testing.T) *ebpf.Collection {
	t.Helper()
	path := testTLSFPObjectPath()
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("load BPF ELF %s (compile with clang … -c bpf/netra_tlsfp.c -o /tmp/netra_tlsfp.o): %v", path, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load TLSFP collection: %v", err)
	}
	t.Cleanup(coll.Close)
	return coll
}

// TestTLSFPCollectionLoads guards the ELF/maps/program surface that the
// agent attaches — compile + verifier acceptance on the CI kernel.
func TestTLSFPCollectionLoads(t *testing.T) {
	coll := loadTLSFP(t)
	if coll.Programs["netra_tlsfp_egress"] == nil {
		t.Fatal("netra_tlsfp_egress missing")
	}
	for _, name := range []string{"tls_hello_events", "tls_hello_rate", "tls_hello_scratch"} {
		if coll.Maps[name] == nil {
			t.Fatalf("map %s missing", name)
		}
	}
}

// TestTLSFPEgressAllowReturn proves the observe-only cgroup_skb program
// returns 1 (allow) on synthetic packets. Emitting into tls_hello_rate under
// BPF_PROG_TEST_RUN is not reliable for cgroup_skb (TCP payload /
// load_bytes visibility differs from a real socket skb — same class of
// limitation as bpf_get_current_cgroup_id()==0 documented in
// netpol_portonly_test.go). Live emit coverage is scripts/ci-tlsfp-smoke.sh.
func TestTLSFPEgressAllowReturn(t *testing.T) {
	coll := loadTLSFP(t)
	prog := coll.Programs["netra_tlsfp_egress"]
	pkt := buildIPv4TCPWithPayload(
		net.ParseIP("10.0.0.1"), net.ParseIP("1.2.3.4"),
		12345, 443, tcpACK, minimalClientHello(),
	)
	ret, _, err := prog.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test: %v", err)
	}
	if ret != 1 {
		t.Fatalf("cgroup_skb must return 1 (allow), got %d", ret)
	}

	// Best-effort: if this kernel does surface payload under TEST_RUN, the
	// rate map should gain an entry — log only, never fail CI on absence.
	rateMap := coll.Maps["tls_hello_rate"]
	iter := rateMap.Iterate()
	var key uint64
	var val struct{ LastNS uint64 }
	if iter.Next(&key, &val) {
		t.Logf("PROG_TEST_RUN emitted rate key=%d (bonus on this kernel)", key)
	} else {
		t.Log("PROG_TEST_RUN did not populate tls_hello_rate (expected on many kernels; live smoke covers emit)")
	}
}

func TestTLSFPIgnoresNonTLS(t *testing.T) {
	coll := loadTLSFP(t)
	prog := coll.Programs["netra_tlsfp_egress"]
	rateMap := coll.Maps["tls_hello_rate"]

	pkt := buildIPv4TCPWithPayload(
		net.ParseIP("10.0.0.1"), net.ParseIP("9.9.9.9"),
		1111, 80, tcpACK, []byte("GET / HTTP/1.1\r\n\r\n"),
	)
	if _, _, err := prog.Test(pkt); err != nil {
		t.Fatal(err)
	}
	iter := rateMap.Iterate()
	var key uint64
	var val struct{ LastNS uint64 }
	if iter.Next(&key, &val) {
		t.Fatalf("unexpected rate entry for cleartext HTTP key=%d", key)
	}
}
