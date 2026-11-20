//go:build linux

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Reject paths outside the host cgroup mount and require the full inspected
// container ID in an exact path component (Docker cgroupfs or systemd layout).
func dockerCgroupPath(contents, id string) (string, error) {
	var found string
	for _, line := range strings.Split(strings.TrimSpace(contents), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		p := parts[2]
		if found != "" || !strings.HasPrefix(p, "/") || filepath.Clean(p) != p {
			return "", fmt.Errorf("ambiguous or noncanonical cgroup-v2 path")
		}
		matched := false
		for _, component := range strings.Split(p, "/") {
			if component == id || component == "docker-"+id+".scope" {
				matched = true
			}
		}
		if !matched {
			return "", fmt.Errorf("host cgroup path does not contain the inspected full container ID; use the Docker host's PID/cgroup namespaces")
		}
		found = p
	}
	if found == "" {
		return "", fmt.Errorf("Docker discovery requires a visible host cgroup-v2 path")
	}
	return found, nil
}
func localDockerCgroup(c dockerContainer) (uint64, error) {
	proc := filepath.Join("/proc", strconv.Itoa(c.State.PID), "cgroup")
	b, e := os.ReadFile(proc)
	if e != nil {
		return 0, fmt.Errorf("read container host cgroup: %w", e)
	}
	relative, e := dockerCgroupPath(string(b), c.ID)
	if e != nil {
		return 0, e
	}
	root := "/sys/fs/cgroup"
	target := filepath.Join(root, strings.TrimPrefix(relative, "/"))
	actual, e := filepath.EvalSymlinks(target)
	if e != nil {
		return 0, e
	}
	if actual != target {
		return 0, fmt.Errorf("container cgroup path contains symbolic links")
	}
	var fs syscall.Statfs_t
	if e = syscall.Statfs(target, &fs); e != nil {
		return 0, e
	}
	if uint64(fs.Type) != 0x63677270 {
		return 0, fmt.Errorf("container cgroup is not on a cgroup-v2 filesystem")
	}
	info, e := os.Stat(target)
	if e != nil {
		return 0, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Ino == 0 {
		return 0, fmt.Errorf("container cgroup inode is unavailable")
	}
	// Re-read the PID's cgroup to catch movement during lookup.
	again, e := os.ReadFile(proc)
	if e != nil {
		return 0, e
	}
	if string(again) != string(b) {
		return 0, fmt.Errorf("container process moved cgroups during lookup; retry")
	}
	return st.Ino, nil
}
