// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysres

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// SampleStacks reads /proc/<pid>/stack for the hottest comms. The file is
// a kernel stack and is often unreadable without privilege; those PIDs
// are skipped. No argv, cmdline, or environ is opened.
func SampleStacks(root string, tops models.HostProcessTops, n, depth int) []models.StackSample {
	if n <= 0 {
		n = 5
	}
	if depth <= 0 || depth > 32 {
		depth = 16
	}
	var out []models.StackSample
	for _, p := range tops.ByCPU {
		if len(out) >= n {
			break
		}
		if p.PID == 0 {
			continue
		}
		folded, frames := readKernelStack(root, p.PID, p.Comm, depth)
		wchan := readWchan(root, p.PID)
		if frames == 0 && wchan == "" {
			continue
		}
		out = append(out, models.StackSample{PID: p.PID, Comm: p.Comm, Folded: folded, Frames: frames, Wchan: wchan})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readKernelStack(root string, pid uint32, comm string, depth int) (string, int) {
	b, err := os.ReadFile(filepath.Join(root, "proc", strconv.FormatUint(uint64(pid), 10), "stack"))
	if err != nil {
		return "", 0
	}
	var frames []string
	for _, line := range strings.Split(string(b), "\n") {
		name := stackFrame(line)
		if name == "" {
			continue
		}
		frames = append(frames, name)
		if len(frames) >= depth {
			break
		}
	}
	if len(frames) == 0 {
		return "", 0
	}
	// /proc/pid/stack prints the current frame first. Folded order is
	// outermost first, leaf last.
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	if comm == "" {
		comm = "unknown"
	}
	return comm + ";" + strings.Join(frames, ";"), len(frames)
}

func stackFrame(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if i := strings.Index(line, "]"); i >= 0 && i+1 < len(line) {
		line = strings.TrimSpace(line[i+1:])
	}
	if i := strings.Index(line, "+"); i > 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "0x") {
		return ""
	}
	return line
}

func readWchan(root string, pid uint32) string {
	b, err := os.ReadFile(filepath.Join(root, "proc", strconv.FormatUint(uint64(pid), 10), "wchan"))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "0" {
		return ""
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
