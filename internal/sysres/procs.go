// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysres

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

const (
	// HostProcessTopN is how many processes each ranking keeps. The agent
	// report and the drop-incident JSON both use this cap.
	HostProcessTopN = 10
	// userHZ is Linux USER_HZ, the unit of utime/stime in /proc/<pid>/stat.
	userHZ = 100
)

// ProcSample is one process's comm, cumulative CPU jiffies, and RSS.
// Comm comes from /proc/<pid>/stat, never from cmdline.
type ProcSample struct {
	PID      uint32
	Comm     string
	Jiffies  uint64
	RSSBytes uint64
}

// SampleProcesses reads root/proc/<pid>/stat and status for every numeric
// pid. A missing or unreadable process is skipped. This is best-effort and
// never returns an error.
func SampleProcesses(root string) []ProcSample {
	if root == "" {
		root = "/"
	}
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return nil
	}
	out := make([]ProcSample, 0, len(entries))
	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		dir := filepath.Join(root, "proc", e.Name())
		comm, jiffies, ok := readProcStat(filepath.Join(dir, "stat"))
		if !ok {
			continue
		}
		out = append(out, ProcSample{
			PID:      uint32(pid64),
			Comm:     comm,
			Jiffies:  jiffies,
			RSSBytes: readVmRSS(filepath.Join(dir, "status")),
		})
	}
	return out
}

// TopHostProcesses ranks cur by CPU% (delta against prev jiffies) and by
// RSS. elapsedSeconds <= 0, or a pid with no previous sample, yields
// CPUPercent 0. next is the jiffy map to keep for the following tick;
// pids that disappeared are dropped.
func TopHostProcesses(prev map[uint32]uint64, cur []ProcSample, elapsedSeconds float64) (byCPU, byRSS []models.HostProcessStat, next map[uint32]uint64) {
	next = make(map[uint32]uint64, len(cur))
	stats := make([]models.HostProcessStat, 0, len(cur))
	for _, p := range cur {
		next[p.PID] = p.Jiffies
		st := models.HostProcessStat{PID: p.PID, Comm: p.Comm, RSSBytes: p.RSSBytes}
		if elapsedSeconds > 0 {
			if old, ok := prev[p.PID]; ok && p.Jiffies >= old {
				st.CPUPercent = float64(p.Jiffies-old) / userHZ / elapsedSeconds * 100
			}
		}
		stats = append(stats, st)
	}
	byCPU = append([]models.HostProcessStat(nil), stats...)
	sort.SliceStable(byCPU, func(i, j int) bool {
		if byCPU[i].CPUPercent != byCPU[j].CPUPercent {
			return byCPU[i].CPUPercent > byCPU[j].CPUPercent
		}
		return byCPU[i].PID < byCPU[j].PID
	})
	byRSS = append([]models.HostProcessStat(nil), stats...)
	sort.SliceStable(byRSS, func(i, j int) bool {
		if byRSS[i].RSSBytes != byRSS[j].RSSBytes {
			return byRSS[i].RSSBytes > byRSS[j].RSSBytes
		}
		return byRSS[i].PID < byRSS[j].PID
	})
	if len(byCPU) > HostProcessTopN {
		byCPU = byCPU[:HostProcessTopN]
	}
	if len(byRSS) > HostProcessTopN {
		byRSS = byRSS[:HostProcessTopN]
	}
	if len(byCPU) == 0 {
		byCPU = nil
	}
	if len(byRSS) == 0 {
		byRSS = nil
	}
	return byCPU, byRSS, next
}

func readProcStat(path string) (comm string, jiffies uint64, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, false
	}
	s := string(b)
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close <= open {
		return "", 0, false
	}
	comm = cleanComm(s[open+1 : close])
	rest := strings.Fields(s[close+1:])
	// After ')': state, ppid, pgrp, session, tty_nr, tpgid, flags,
	// minflt, cminflt, majflt, cmajflt, utime, stime.
	if len(rest) < 13 {
		return "", 0, false
	}
	utime, err1 := strconv.ParseUint(rest[11], 10, 64)
	stime, err2 := strconv.ParseUint(rest[12], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, false
	}
	return comm, utime + stime, true
}

func readVmRSS(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok || key != "VmRSS" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

func cleanComm(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
