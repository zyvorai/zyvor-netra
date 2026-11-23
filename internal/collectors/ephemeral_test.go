// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package collectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func tcpLine(i int, local, remote, st string) string {
	return fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n", i, local, remote, st, 1000+i)
}

func ephemeralFixture(t *testing.T, rng string, files map[string]string) fsys {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/net/ipv4"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if rng != "" {
		if err := os.WriteFile(filepath.Join(root, "sys/net/ipv4/ip_local_port_range"), []byte(rng), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return fsys{proc: root, sys: root}
}

func runEphemeral(t *testing.T, f fsys) found {
	t.Helper()
	e := NewEmitter()
	e.Begin(time.Unix(1_700_000_000, 0))
	if err := (&EphemeralPorts{fs: f}).Collect(e.now, e); err != nil {
		t.Fatal(err)
	}
	out := found{}
	for _, s := range e.Samples() {
		out[s.Context+"/"+s.Dimension] = s.V
	}
	return out
}

func TestEphemeralPortsBusiestDestination(t *testing.T) {
	// range 32768-32777 (size 10). Ports 0x8000=32768.. 0x8003.
	tcp := tcpHeader +
		tcpLine(0, "0100007F:8000", "0200007F:0050", "01") + // 4 to one destination
		tcpLine(1, "0100007F:8001", "0200007F:0050", "06") + // TIME_WAIT counts
		tcpLine(2, "0100007F:8002", "0200007F:0050", "01") +
		tcpLine(3, "0100007F:8003", "0200007F:0050", "01") +
		tcpLine(4, "0100007F:8004", "0300007F:01BB", "01") + // another destination
		tcpLine(5, "0100007F:8005", "00000000:0000", "0A") + // listener in range: ignored
		tcpLine(6, "0100007F:0050", "0200007F:9999", "01") // local port outside range: ignored
	udp := tcpHeader + tcpLine(0, "0100007F:8006", "00000000:0000", "07")
	got := runEphemeral(t, ephemeralFixture(t, "32768\t32777\n", map[string]string{"tcp": tcp, "udp": udp}))
	if got["net.ephemeral_ports/in_use"] != 6 || got["net.ephemeral_ports/max_per_destination"] != 4 || got["net.ephemeral_ports/range_size"] != 10 {
		t.Fatalf("%v", got)
	}
	if got["net.ephemeral_utilization/used"] != 40 {
		t.Fatalf("utilization %v", got)
	}
	if got["net.ephemeral_truncated/truncated"] != 0 {
		t.Fatalf("truncated %v", got)
	}
}

func TestEphemeralPortsHostileInput(t *testing.T) {
	bad := tcpHeader +
		"garbage\n" +
		"\n" +
		"   0: nocolon 0200007F:0050 01\n" +
		"   1: 0100007F:ZZZZ 0200007F:0050 01\n" +
		"   2: 0100007F:123456789 0200007F:0050 01\n" +
		"   3: 0100007F:8000 nocolon 01\n" +
		"   4: 0100007F: 0200007F:0050 01\n" +
		"   5: :8000 0200007F:0050 01\n" +
		"   6: 0100007F:8000\n" +
		tcpLine(7, "0100007F:8000", "0200007F:0050", "01") +
		strings.Repeat("x", 100000) + "\n" + // longer than the scanner limit: scanning stops, it must not panic
		tcpLine(8, "0100007F:8001", "0200007F:0050", "01")
	got := runEphemeral(t, ephemeralFixture(t, "32768 60999", map[string]string{"tcp": bad}))
	if got["net.ephemeral_ports/in_use"] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestEphemeralPortsBadRange(t *testing.T) {
	for _, rng := range []string{"", "x y", "100", "5 1", "0 10", "1 70000", "1 2 3"} {
		f := ephemeralFixture(t, rng, map[string]string{"tcp": tcpHeader})
		e := NewEmitter()
		e.Begin(time.Unix(1, 0))
		err := (&EphemeralPorts{fs: f}).Collect(e.now, e)
		if rng == "" && err == nil {
			t.Fatalf("missing range file should error")
		}
		if len(e.Samples()) != 0 {
			t.Fatalf("range %q emitted %v", rng, e.Samples())
		}
	}
}

func TestEphemeralPortsMissingFilesAndCardinalityCap(t *testing.T) {
	// no tcp6/udp files at all: fine.
	got := runEphemeral(t, ephemeralFixture(t, "1000 1010", map[string]string{"tcp": tcpHeader}))
	if got["net.ephemeral_ports/in_use"] != 0 {
		t.Fatalf("%v", got)
	}
	// Many distinct destinations hit the key cap and flag truncation without
	// growing memory without bound.
	s := &ephemeralScan{perDest: map[string]int{}}
	dir := t.TempDir()
	p := filepath.Join(dir, "tcp")
	var b strings.Builder
	b.WriteString(tcpHeader)
	for i := 0; i < ephemeralMaxKeys+50; i++ {
		b.WriteString(tcpLine(i, "0100007F:8000", fmt.Sprintf("%08X:0050", i), "01"))
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	s.file(p, 32768, 60999, true)
	if !s.truncated || len(s.perDest) != ephemeralMaxKeys {
		t.Fatalf("truncated=%v keys=%d", s.truncated, len(s.perDest))
	}
}

func TestEphemeralPortsIntervalAndRegistration(t *testing.T) {
	if (&EphemeralPorts{}).Info().Every != 10*time.Second {
		t.Fatal("default interval should be 10s")
	}
	found := false
	for _, c := range Host(Config{}) {
		if _, ok := c.(*EphemeralPorts); ok {
			found = true
		}
	}
	if !found {
		t.Fatal("EphemeralPorts is not part of Host()")
	}
}
