// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package rtnlactor

import (
	"os"
	"syscall"
)

// SelfNetNS is the inode of this process's network namespace, 0 if it cannot be
// read. The agent runs hostNetwork, so for it this is the host's namespace, which is
// the one its netlink recorder subscribes in and the only one whose requests explain
// the changes it records.
func SelfNetNS() uint32 {
	fi, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint32(st.Ino)
	}
	return 0
}
