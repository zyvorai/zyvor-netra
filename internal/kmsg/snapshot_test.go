// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package kmsg

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// snapshotWithin runs Snapshot and fails, rather than hanging the test binary,
// if it does not return in time.
func snapshotWithin(t *testing.T, path string, d time.Duration) string {
	t.Helper()
	done := make(chan string, 1)
	go func() { done <- Snapshot(path) }()
	select {
	case s := <-done:
		return s
	case <-time.After(d):
		t.Fatalf("Snapshot(%s) did not return within %s: it blocks at the end of the data", path, d)
		return ""
	}
}

// A FIFO with a writer attached and nothing more to read behaves like the end
// of /dev/kmsg's ring buffer: a non-blocking read returns EAGAIN. This is the
// regression case: with os.OpenFile+O_NONBLOCK the goroutine parked in Go's
// poller here forever.
func TestSnapshotReturnsAtTheEndOfTheDataInsteadOfBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "kmsg-like")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	// O_RDWR keeps a writer attached without blocking the open, so the reader
	// sees "no data yet" (EAGAIN), not EOF.
	w, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Skipf("cannot open the FIFO: %v", err)
	}
	defer w.Close()

	if got := snapshotWithin(t, fifo, 3*time.Second); got != "" {
		t.Fatalf("an empty stream produced %q", got)
	}
	if _, err := w.WriteString("6,1,100,-;first record\n"); err != nil {
		t.Fatal(err)
	}
	got := snapshotWithin(t, fifo, 3*time.Second)
	if !strings.Contains(got, "first record") {
		t.Fatalf("Snapshot = %q, want the data that was there, then a clean return", got)
	}
}

func TestSnapshotOfAMissingDeviceIsEmpty(t *testing.T) {
	if got := snapshotWithin(t, "/nonexistent/kmsg", time.Second); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestSnapshotIsCappedAtItsByteLimit(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(f, []byte(strings.Repeat("x", 3*maxBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	got := snapshotWithin(t, f, 3*time.Second)
	if len(got) < maxBytes || len(got) > maxBytes+recordBuf {
		t.Fatalf("read %d bytes, want about the %d cap", len(got), maxBytes)
	}
}

// The real device, where readable. A quiet CI runner or fresh VM has few kernel
// messages, so the read reaches the end of the ring buffer: exactly the case that
// used to hang.
func TestSnapshotOfTheRealKernelLogReturns(t *testing.T) {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		t.Skipf("/dev/kmsg is not readable here: %v", err)
	}
	_ = f.Close()
	got := snapshotWithin(t, "/dev/kmsg", 5*time.Second)
	t.Logf("read %d bytes of the kernel log", len(got))
}
