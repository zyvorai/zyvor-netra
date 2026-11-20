// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux && bpfintegration

package bpfintegration

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// sendDrops fires n UDP datagrams at a port nobody listens on, each of which the
// kernel drops (reason NO_SOCKET). An unconnected socket is used so the ICMP
// "port unreachable" reply does not turn later sends into errors. It returns the
// wall-clock time of the loop.
func sendDrops(t *testing.T, n int) time.Duration {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	dst := &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	payload := []byte("x")
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := syscall.Sendto(fd, payload, 0, dst); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	return time.Since(start)
}

// Measures what the drop attribution costs per dropped packet, from the kernel's
// own BPF run-time accounting, and the effect on a loop that does nothing but
// generate drops (the worst case: the sensor runs on every packet). It always
// runs, with a small count, so a pathological regression is caught; set
// NETRA_BPF_COST_N for a longer, steadier measurement.
func TestDropInfoCostPerDrop(t *testing.T) {
	n := 100000
	if v, err := strconv.Atoi(os.Getenv("NETRA_BPF_COST_N")); err == nil && v > 0 {
		n = v
	}
	closer, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		t.Skipf("cannot enable BPF run-time statistics: %v", err)
	}
	defer closer.Close()

	// Warm up and measure the baseline without the sensor.
	sendDrops(t, n/10)
	base := sendDrops(t, n)

	s := loadDropInfo(t)
	sendDrops(t, n/10)
	runs0, spent0, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	with := sendDrops(t, n)
	runs1, spent1, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	runs, spent := runs1-runs0, spent1-spent0

	// Every datagram is one drop; other traffic on the host adds a few.
	if runs < uint64(n) {
		t.Fatalf("the program ran %d times for %d drops", runs, n)
	}
	perRun := time.Duration(int64(spent) / int64(runs))
	perSend := func(d time.Duration) time.Duration { return d / time.Duration(n) }
	extra := perSend(with) - perSend(base)
	t.Logf("%d drops: program ran %d times, %.0f ns per run (kernel accounting)", n, runs, float64(perRun))
	t.Logf("send loop: %v per datagram without the sensor, %v with it (%+v per drop, %.1f%%)",
		perSend(base), perSend(with), extra, 100*float64(extra)/float64(perSend(base)))

	// A generous ceiling: this catches an accidental order-of-magnitude
	// regression (a loop, a huge copy) without flaking on a busy shared runner.
	if perRun > 50*time.Microsecond {
		t.Fatalf("%v per drop is far beyond what a handful of map updates should cost", perRun)
	}

	// The counters must still be right after the load.
	sn := dropSnap(t, s)
	if sn.Totals.Drops < uint64(n) || sn.Totals.MapFull != 0 || sn.Totals.ReadError != 0 {
		t.Fatalf("totals under load = %+v, want >= %d drops and no map-full or read errors", sn.Totals, n)
	}
}
