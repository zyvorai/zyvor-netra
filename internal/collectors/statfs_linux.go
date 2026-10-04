// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package collectors

import "golang.org/x/sys/unix"

func platformStatfs(path string) (fsUsage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsUsage{}, err
	}
	return fsUsage{
		BlockSize: uint64(st.Bsize), Blocks: st.Blocks, Free: st.Bfree, Avail: st.Bavail,
		Inodes: st.Files, InodesFree: st.Ffree,
	}, nil
}
