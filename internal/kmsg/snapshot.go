// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package kmsg

import (
	"bytes"
	"syscall"
)

const (
	// maxBytes caps one snapshot.
	maxBytes = 256 << 10
	// recordBuf must hold a whole /dev/kmsg record (the kernel allows up to 8 KiB
	// and rejects a smaller read buffer with EINVAL).
	recordBuf = 8192
	// maxSkips bounds how many overwritten-record errors one snapshot tolerates.
	maxSkips = 1024
)

// Snapshot reads up to 256KiB from path without blocking. /dev/kmsg is the
// usual path. A missing device returns an empty string.
//
// It uses raw non-blocking read(2) calls on purpose. os.OpenFile with O_NONBLOCK
// on a pollable device (which /dev/kmsg is) hands the descriptor to Go's network
// poller, and a read that would return EAGAIN then parks the goroutine until the
// device becomes readable instead of returning: at the end of the kernel ring
// buffer that is forever on a quiet host, and the agent's report loop, which
// calls this, never came back. Only a host whose buffer held more than the cap
// (a busy, long-running one) avoided it, so a fresh node, a kind cluster or a CI
// runner hung on its very first report.
func Snapshot(path string) string {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	defer syscall.Close(fd)

	var buf bytes.Buffer
	tmp := make([]byte, recordBuf)
	skips := 0
	for buf.Len() < maxBytes {
		n, err := syscall.Read(fd, tmp)
		switch {
		case err == syscall.EINTR:
			continue
		case err == syscall.EPIPE:
			// /dev/kmsg: the record we were positioned on was overwritten; the
			// next read continues from the oldest surviving one.
			if skips++; skips > maxSkips {
				return buf.String()
			}
			continue
		case err != nil || n <= 0:
			// EAGAIN is the normal end of the ring buffer; anything else, or EOF,
			// also ends the snapshot with what was read.
			return buf.String()
		}
		buf.Write(tmp[:n])
	}
	return buf.String()
}
