// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// memLimitFraction is how much of the container's memory limit the Go heap is
// allowed to grow to before the collector works harder. The rest is headroom
// for stacks, runtime metadata and the JSON buffers of in-flight requests.
const memLimitFraction = 85

// applyMemoryLimit sets Go's soft memory limit from the container's cgroup
// limit unless GOMEMLIMIT is already set.
//
// Without it the collector only reacts to heap growth (GOGC), never to the
// container limit, so a process with a large live heap and bursts of garbage
// (here: a 100k-record flow history plus 2-3 MB agent reports every few
// seconds) lets the heap run to roughly twice its live size and is then
// OOM-killed, restarts, reloads the same state and does it again. A soft limit
// makes the collector tighten as it nears the ceiling. It cannot help if the
// live heap itself exceeds the limit, which is what the chart's larger default
// limit is for.
func applyMemoryLimit(log *slog.Logger) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	limit, ok := cgroupMemoryLimit("/sys/fs/cgroup")
	if !ok {
		return
	}
	soft := limit / 100 * memLimitFraction
	debug.SetMemoryLimit(int64(soft))
	log.Info("go memory limit set from the container's cgroup limit", "cgroupLimitBytes", limit, "softLimitBytes", soft)
}

// cgroupMemoryLimit reads the container's memory limit under root, trying
// cgroup v2 (memory.max) and then v1 (memory/memory.limit_in_bytes).
func cgroupMemoryLimit(root string) (uint64, bool) {
	for _, rel := range []string{"memory.max", filepath.Join("memory", "memory.limit_in_bytes")} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		if n, ok := parseCgroupLimit(string(b)); ok {
			return n, true
		}
	}
	return 0, false
}

// parseCgroupLimit reads a cgroup limit file. "max" (v2) and the huge
// sentinel v1 reports for "no limit" mean unlimited, which is not a limit to
// derive anything from; nor is a value too small to be a real container.
func parseCgroupLimit(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	const unlimitedAbove = 1 << 60 // v1 "no limit" is 9223372036854771712
	const tooSmall = 16 << 20
	if n >= unlimitedAbove || n < tooSmall {
		return 0, false
	}
	return n, true
}
