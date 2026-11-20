// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package sysres collects a per-node, "top"-like system resource
// snapshot: host CPU/memory/load average plus per-workload cgroup v2
// CPU/memory usage. Unlike internal/sysctlaudit, most values here are
// cumulative counters (CPU jiffies, cgroup usage_usec), not current
// settings — a rate needs two samples, so the agent keeps its own
// previous-tick sample and computes percentages itself before a report
// ever reaches the controller. internal/sysres.Build (the stateless,
// per-request aggregator) never sees raw counters, only already-computed
// percentages.
//
// Workload attribution is cgroup v2-based, reusing the CgroupPath every
// WorkloadIdentity already carries — not a full host PID scan. The
// node-resources view does not list raw processes. A separate bounded
// comm-only top (SampleProcesses) exists only so a drop-incident snapshot
// can name host daemons; it never includes argv or cmdline.
package sysres

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// HostCPUJiffies is /proc/stat's "cpu " line, in USER_HZ jiffies since boot.
type HostCPUJiffies struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

// Total returns the sum of every jiffie field — the denominator
// ComputeCPUPercent needs.
func (j HostCPUJiffies) Total() uint64 {
	return j.User + j.Nice + j.System + j.Idle + j.IOWait + j.IRQ + j.SoftIRQ + j.Steal
}

// Busy returns every jiffie field except Idle and IOWait — time spent
// doing anything other than being idle or blocked on I/O.
func (j HostCPUJiffies) Busy() uint64 {
	return j.Total() - j.Idle - j.IOWait
}

// HostSample is one point-in-time read of every host-level source file.
// Each field is independently best-effort: a missing/unreadable file
// (a restricted container, an unsupported kernel) just leaves its zero
// value rather than failing the whole sample, the same "never an error"
// ethos internal/sysctlaudit/internal/kerneldiag already use.
type HostSample struct {
	CPU           HostCPUJiffies
	LoadAvg1      float64
	LoadAvg5      float64
	LoadAvg15     float64
	MemTotalKB    uint64
	MemFreeKB     uint64
	MemAvailKB    uint64
	MemCachedKB   uint64
	UptimeSeconds uint64
	CPUCores      int
	Hostname      string
	KernelRelease string
}

// Sample reads root's (typically "/", a fixture directory in tests)
// /proc/stat, /proc/loadavg, /proc/meminfo, /proc/uptime, and
// /proc/cpuinfo into one HostSample.
func Sample(root string) HostSample {
	if root == "" {
		root = "/"
	}
	var s HostSample
	s.CPU = readProcStatCPU(root)
	s.LoadAvg1, s.LoadAvg5, s.LoadAvg15 = readLoadAvg(root)
	s.MemTotalKB, s.MemFreeKB, s.MemAvailKB, s.MemCachedKB = readMemInfo(root)
	s.UptimeSeconds = readUptime(root)
	s.CPUCores = countCPUCores(root)
	s.Hostname = readTrimmed(root, "proc/sys/kernel/hostname")
	s.KernelRelease = readTrimmed(root, "proc/sys/kernel/osrelease")
	return s
}

func readProcStatCPU(root string) HostCPUJiffies {
	var j HostCPUJiffies
	b, err := os.ReadFile(filepath.Join(root, "proc/stat"))
	if err != nil {
		return j
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[0] != "cpu" {
			continue
		}
		vals := make([]uint64, 8)
		for i := range 8 {
			vals[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
		}
		j = HostCPUJiffies{User: vals[0], Nice: vals[1], System: vals[2], Idle: vals[3], IOWait: vals[4], IRQ: vals[5], SoftIRQ: vals[6], Steal: vals[7]}
		break
	}
	return j
}

func readLoadAvg(root string) (l1, l5, l15 float64) {
	b, err := os.ReadFile(filepath.Join(root, "proc/loadavg"))
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	l1, _ = strconv.ParseFloat(fields[0], 64)
	l5, _ = strconv.ParseFloat(fields[1], 64)
	l15, _ = strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15
}

func readMemInfo(root string) (totalKB, freeKB, availKB, cachedKB uint64) {
	b, err := os.ReadFile(filepath.Join(root, "proc/meminfo"))
	if err != nil {
		return 0, 0, 0, 0
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			totalKB = v
		case "MemFree":
			freeKB = v
		case "MemAvailable":
			availKB = v
		case "Cached":
			cachedKB = v
		}
	}
	return totalKB, freeKB, availKB, cachedKB
}

func readUptime(root string) uint64 {
	b, err := os.ReadFile(filepath.Join(root, "proc/uptime"))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(f)
}

func countCPUCores(root string) int {
	b, err := os.ReadFile(filepath.Join(root, "proc/cpuinfo"))
	if err != nil {
		return 0
	}
	n := 0
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(line, "processor") {
			n++
		}
	}
	return n
}

func readTrimmed(root, rel string) string {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ComputeCPUPercent returns the percentage of wall-clock time spent busy
// (not idle, not I/O-wait) between two HostCPUJiffies samples. Returns 0
// if elapsedSeconds isn't positive or the counters didn't advance (a
// first sample, a counter reset, or two samples taken too close
// together) — never a negative or NaN/Inf value.
func ComputeCPUPercent(prev, cur HostCPUJiffies, elapsedSeconds float64) float64 {
	if elapsedSeconds <= 0 {
		return 0
	}
	totalDelta := cur.Total() - prev.Total()
	if cur.Total() < prev.Total() || totalDelta == 0 {
		return 0
	}
	busyDelta := cur.Busy() - prev.Busy()
	if cur.Busy() < prev.Busy() {
		return 0
	}
	pct := float64(busyDelta) / float64(totalDelta) * 100
	if pct < 0 {
		return 0
	}
	return pct
}

// WorkloadSample is one cgroup v2 directory's raw resource counters.
type WorkloadSample struct {
	UsageUsec        uint64
	MemoryUsedBytes  uint64
	MemoryLimitBytes uint64 // 0 = unlimited ("max")
}

// SampleWorkload reads cgroupPath's cpu.stat, memory.current, and
// memory.max. cgroupPath is expected to already be an absolute,
// directly-readable filesystem path (WorkloadIdentity.CgroupPath is
// populated this way by internal/cgroupmeta.Scan). Returns false if
// cpu.stat can't be read at all (the cgroup has already been torn down,
// or this isn't a real cgroup v2 directory) — a partial read of the two
// memory files still returns their best-effort values in that case is
// not attempted, since a torn-down cgroup's memory files are equally
// gone.
func SampleWorkload(cgroupPath string) (WorkloadSample, bool) {
	if cgroupPath == "" {
		return WorkloadSample{}, false
	}
	usage, ok := readCgroupCPUUsageUsec(cgroupPath)
	if !ok {
		return WorkloadSample{}, false
	}
	used := readCgroupUint(filepath.Join(cgroupPath, "memory.current"))
	limit := readCgroupMemoryMax(cgroupPath)
	return WorkloadSample{UsageUsec: usage, MemoryUsedBytes: used, MemoryLimitBytes: limit}, true
}

func readCgroupCPUUsageUsec(cgroupPath string) (uint64, bool) {
	b, err := os.ReadFile(filepath.Join(cgroupPath, "cpu.stat"))
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		key, rest, ok := strings.Cut(line, " ")
		if !ok || key != "usage_usec" {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

func readCgroupUint(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// HostSnapshot assembles a models.HostResourceSnapshot from cur, using
// prev/prevAt to compute CPUPercent when a prior sample exists.
// prevAt.IsZero() (the agent's first tick since start) leaves CPUPercent
// at 0 rather than computing a delta against a meaningless zero-value
// prev sample.
func HostSnapshot(prev, cur HostSample, prevAt, now time.Time) models.HostResourceSnapshot {
	var cpuPct float64
	if !prevAt.IsZero() {
		cpuPct = ComputeCPUPercent(prev.CPU, cur.CPU, now.Sub(prevAt).Seconds())
	}
	// MemAvailable (kernel 3.14+) is a better "usable" estimate than
	// MemFree alone (it accounts for reclaimable cache), but fall back to
	// MemFree if MemAvailable is missing/zero or looks impossible (a
	// pre-3.14 kernel /proc/meminfo simply has no MemAvailable line).
	availKB := cur.MemAvailKB
	if availKB == 0 || availKB > cur.MemTotalKB {
		availKB = cur.MemFreeKB
	}
	usedKB := uint64(0)
	if cur.MemTotalKB > availKB {
		usedKB = cur.MemTotalKB - availKB
	}
	return models.HostResourceSnapshot{
		LoadAvg1:             cur.LoadAvg1,
		LoadAvg5:             cur.LoadAvg5,
		LoadAvg15:            cur.LoadAvg15,
		CPUCores:             cur.CPUCores,
		CPUPercent:           cpuPct,
		MemoryTotalBytes:     cur.MemTotalKB * 1024,
		MemoryUsedBytes:      usedKB * 1024,
		MemoryAvailableBytes: availKB * 1024,
		MemoryCachedBytes:    cur.MemCachedKB * 1024,
		UptimeSeconds:        cur.UptimeSeconds,
		Hostname:             cur.Hostname,
		KernelRelease:        cur.KernelRelease,
	}
}

// readCgroupMemoryMax returns 0 for both "max" (unlimited) and any
// unreadable/unparseable value — the API/UI already treats 0 as
// "unlimited or unknown" via WorkloadResourceStat.MemoryLimitBytes's
// omitempty, so no separate bool is needed here.
func readCgroupMemoryMax(cgroupPath string) uint64 {
	b, err := os.ReadFile(filepath.Join(cgroupPath, "memory.max"))
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	if s == "max" || s == "" {
		return 0
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}
