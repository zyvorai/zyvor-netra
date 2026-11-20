// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package afcapture

import "golang.org/x/sys/unix"

// Available reports whether this process can open an AF_PACKET/SOCK_RAW
// socket — i.e. whether it holds CAP_NET_RAW. Mirrors
// internal/agent.kfreeDropReasonAvailable()'s role as a cheap pre-attach
// capability probe: called once when a backend: "afpacket" session is
// first requested, not on every reconcile tick. A bare open+close (no
// interface bind) is enough to detect an EPERM denial without any of the
// cost of setting up a real capture.
func Available() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}
