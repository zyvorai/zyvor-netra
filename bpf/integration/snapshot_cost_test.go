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
)

// A busy host fills both flow tables: on a real node they held ~15 600 and
// ~13 000 entries. Each report reads every entry (two syscalls apiece) to build
// a top-50 list. These tests fill the tables the same way and bound what one
// snapshot may cost, so that cost cannot creep up unnoticed. Measured: about
// 8 ms (TCP events) and 16 ms (drop info) per snapshot with 12 000 flows.

func snapshotFlows() int {
	if v, err := strconv.Atoi(os.Getenv("NETRA_BPF_COST_FLOWS")); err == nil && v > 0 {
		return v
	}
	return 12000
}

// fillDropFlows makes n distinct drop tuples: one UDP datagram from each of n
// sockets (distinct source ports) to a closed port.
func fillDropFlows(t *testing.T, n int) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	dst := &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	for i := 0; i < n; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatalf("socket %d: %v", i, err)
		}
		if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			_ = syscall.Close(fd)
			t.Fatalf("bind %d: %v", i, err)
		}
		_ = syscall.Sendto(fd, []byte("x"), 0, dst)
		_ = syscall.Close(fd)
	}
}

// fillTCPFlows makes n distinct TCP tuples with a received RST: a dial to a
// closed port from a fresh source port.
func fillTCPFlows(t *testing.T, n int) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	for i := 0; i < n; i++ {
		c, err := net.DialTimeout("tcp4", addr, time.Second)
		if err == nil {
			_ = c.Close()
		}
	}
}

func TestDropInfoSnapshotCostWithAFullFlowTable(t *testing.T) {
	n := snapshotFlows()
	s := loadDropInfo(t)
	fillDropFlows(t, n)
	sn := dropSnap(t, s)
	if len(sn.Flows) < 100 {
		t.Fatalf("only %d flows after %d sends: the table did not fill", len(sn.Flows), n)
	}
	var total time.Duration
	const rounds = 8
	for i := 0; i < rounds; i++ {
		start := time.Now()
		got, err := s.Snapshot(50, 30)
		total += time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Flows) != 50 {
			t.Fatalf("flows = %d, want the top 50", len(got.Flows))
		}
	}
	avg := total / rounds
	t.Logf("drop info Snapshot with ~%d flows in the table: %v each", n, avg)
	if avg > 100*time.Millisecond {
		t.Fatalf("one snapshot takes %v; the agent takes one every few seconds", avg)
	}
}

func TestTCPEventsSnapshotCostWithAFullFlowTable(t *testing.T) {
	n := snapshotFlows()
	s := loadTCPEvents(t, nil)
	fillTCPFlows(t, n)
	var total time.Duration
	const rounds = 8
	for i := 0; i < rounds; i++ {
		start := time.Now()
		got, err := s.Snapshot(50)
		total += time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Flows) != 50 {
			t.Fatalf("flows = %d, want the top 50 (table not filled?)", len(got.Flows))
		}
	}
	avg := total / rounds
	t.Logf("TCP events Snapshot with ~%d flows in the table: %v each", n, avg)
	if avg > 100*time.Millisecond {
		t.Fatalf("one snapshot takes %v; the agent takes one every few seconds", avg)
	}
}
