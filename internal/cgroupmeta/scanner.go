// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package cgroupmeta

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

type Identity struct {
	CgroupID    uint64
	PodUID      string
	ContainerID string
	Path        string
}

var (
	podRe        = regexp.MustCompile(`(?:^|[-/])pod([0-9a-fA-F_\-]{16,})(?:[./-]|$)`)
	containerRes = []*regexp.Regexp{
		regexp.MustCompile(`(?:cri-containerd|crio|docker)-([0-9a-fA-F]{12,64})(?:\.scope)?$`),
		regexp.MustCompile(`/([0-9a-fA-F]{32,64})$`),
	}
)

// Scan walks a cgroup-v2 hierarchy and returns Kubernetes-looking cgroups.
// cgroup v2 IDs correspond to kernfs inode IDs, exposed to eBPF as cgroup IDs.
func Scan(root string) (map[uint64]Identity, error) {
	out := map[uint64]Identity{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path != root {
				return fs.SkipDir
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		uid := podUID(rel)
		if uid == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Ino == 0 {
			return nil
		}
		out[st.Ino] = Identity{CgroupID: st.Ino, PodUID: uid, ContainerID: containerID(rel), Path: path}
		return nil
	})
	return out, err
}

func podUID(path string) string {
	m := podRe.FindStringSubmatch(path)
	if len(m) != 2 {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))
}

func containerID(path string) string {
	base := filepath.Base(path)
	for _, re := range containerRes {
		if m := re.FindStringSubmatch(base); len(m) == 2 {
			return strings.ToLower(m[1])
		}
	}
	return ""
}
