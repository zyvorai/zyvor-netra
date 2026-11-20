// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysres

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSampleReadsAllHostFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "proc/stat"), "cpu  100 10 50 800 20 5 15 0\ncpu0 50 5 25 400 10 2 7 0\n")
	mustWrite(t, filepath.Join(root, "proc/loadavg"), "0.52 0.58 0.59 1/523 12345\n")
	mustWrite(t, filepath.Join(root, "proc/meminfo"), "MemTotal:       16000000 kB\nMemFree:         2000000 kB\nMemAvailable:    8000000 kB\nCached:          3000000 kB\n")
	mustWrite(t, filepath.Join(root, "proc/uptime"), "12345.67 98765.43\n")
	mustWrite(t, filepath.Join(root, "proc/cpuinfo"), "processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\nmodel name\t: x\n")
	mustWrite(t, filepath.Join(root, "proc/sys/kernel/hostname"), "worker-1\n")
	mustWrite(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "6.8.0-netra\n")

	s := Sample(root)

	want := HostCPUJiffies{User: 100, Nice: 10, System: 50, Idle: 800, IOWait: 20, IRQ: 5, SoftIRQ: 15, Steal: 0}
	if s.CPU != want {
		t.Fatalf("CPU = %+v, want %+v", s.CPU, want)
	}
	if s.LoadAvg1 != 0.52 || s.LoadAvg5 != 0.58 || s.LoadAvg15 != 0.59 {
		t.Fatalf("load avg = %v/%v/%v, want 0.52/0.58/0.59", s.LoadAvg1, s.LoadAvg5, s.LoadAvg15)
	}
	if s.MemTotalKB != 16000000 || s.MemFreeKB != 2000000 || s.MemAvailKB != 8000000 || s.MemCachedKB != 3000000 {
		t.Fatalf("meminfo = %+v", s)
	}
	if s.UptimeSeconds != 12345 {
		t.Fatalf("uptime = %d, want 12345", s.UptimeSeconds)
	}
	if s.CPUCores != 2 {
		t.Fatalf("cpu cores = %d, want 2", s.CPUCores)
	}
	if s.Hostname != "worker-1" || s.KernelRelease != "6.8.0-netra" {
		t.Fatalf("identity hostname=%q kernel=%q", s.Hostname, s.KernelRelease)
	}
}

func TestSampleMissingFilesReturnZeroValueNoPanic(t *testing.T) {
	root := t.TempDir() // empty — nothing exists under it
	s := Sample(root)
	if s != (HostSample{}) {
		t.Fatalf("expected zero-value HostSample for missing files, got %+v", s)
	}
}

func TestComputeCPUPercent(t *testing.T) {
	cases := []struct {
		name    string
		prev    HostCPUJiffies
		cur     HostCPUJiffies
		elapsed float64
		want    float64
	}{
		{
			name:    "50% busy over 10s",
			prev:    HostCPUJiffies{User: 100, Idle: 100},
			cur:     HostCPUJiffies{User: 150, Idle: 150},
			elapsed: 10,
			want:    50,
		},
		{
			name:    "fully idle",
			prev:    HostCPUJiffies{User: 100, Idle: 100},
			cur:     HostCPUJiffies{User: 100, Idle: 200},
			elapsed: 10,
			want:    0,
		},
		{
			name:    "fully busy",
			prev:    HostCPUJiffies{User: 100, Idle: 100},
			cur:     HostCPUJiffies{User: 300, Idle: 100},
			elapsed: 10,
			want:    100,
		},
		{
			name:    "zero elapsed time",
			prev:    HostCPUJiffies{User: 100, Idle: 100},
			cur:     HostCPUJiffies{User: 150, Idle: 150},
			elapsed: 0,
			want:    0,
		},
		{
			name:    "counter reset (cur < prev)",
			prev:    HostCPUJiffies{User: 500, Idle: 500},
			cur:     HostCPUJiffies{User: 10, Idle: 10},
			elapsed: 10,
			want:    0,
		},
		{
			name:    "no advance at all",
			prev:    HostCPUJiffies{User: 100, Idle: 100},
			cur:     HostCPUJiffies{User: 100, Idle: 100},
			elapsed: 10,
			want:    0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComputeCPUPercent(tc.prev, tc.cur, tc.elapsed); got != tc.want {
				t.Fatalf("ComputeCPUPercent() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHostSnapshotFirstTickHasZeroCPUPercent(t *testing.T) {
	cur := HostSample{CPU: HostCPUJiffies{User: 100, Idle: 100}, MemTotalKB: 1000, MemAvailKB: 400}
	got := HostSnapshot(HostSample{}, cur, time.Time{}, time.Now())
	if got.CPUPercent != 0 {
		t.Fatalf("CPUPercent = %v, want 0 on the first tick (no prior sample)", got.CPUPercent)
	}
	if got.MemoryUsedBytes != 600*1024 {
		t.Fatalf("MemoryUsedBytes = %d, want %d", got.MemoryUsedBytes, 600*1024)
	}
}

func TestHostSnapshotFallsBackToMemFreeWhenMemAvailableMissing(t *testing.T) {
	// Pre-3.14 kernels have no MemAvailable line; MemAvailKB stays 0.
	cur := HostSample{MemTotalKB: 1000, MemFreeKB: 300}
	got := HostSnapshot(HostSample{}, cur, time.Time{}, time.Now())
	if got.MemoryAvailableBytes != 300*1024 {
		t.Fatalf("MemoryAvailableBytes = %d, want %d (fallback to MemFree)", got.MemoryAvailableBytes, 300*1024)
	}
	if got.MemoryUsedBytes != 700*1024 {
		t.Fatalf("MemoryUsedBytes = %d, want %d", got.MemoryUsedBytes, 700*1024)
	}
}

func TestSampleWorkloadReadsCgroupFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "cpu.stat"), "usage_usec 1234567\nuser_usec 1000000\nsystem_usec 234567\n")
	mustWrite(t, filepath.Join(root, "memory.current"), "104857600\n")
	mustWrite(t, filepath.Join(root, "memory.max"), "209715200\n")

	got, ok := SampleWorkload(root)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.UsageUsec != 1234567 {
		t.Fatalf("UsageUsec = %d, want 1234567", got.UsageUsec)
	}
	if got.MemoryUsedBytes != 104857600 {
		t.Fatalf("MemoryUsedBytes = %d, want 104857600", got.MemoryUsedBytes)
	}
	if got.MemoryLimitBytes != 209715200 {
		t.Fatalf("MemoryLimitBytes = %d, want 209715200", got.MemoryLimitBytes)
	}
}

func TestSampleWorkloadUnlimitedMemoryMax(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "cpu.stat"), "usage_usec 100\n")
	mustWrite(t, filepath.Join(root, "memory.current"), "1000\n")
	mustWrite(t, filepath.Join(root, "memory.max"), "max\n")

	got, ok := SampleWorkload(root)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.MemoryLimitBytes != 0 {
		t.Fatalf("MemoryLimitBytes = %d, want 0 (unlimited)", got.MemoryLimitBytes)
	}
}

func TestSampleWorkloadMissingCgroupReturnsFalse(t *testing.T) {
	root := t.TempDir() // no cpu.stat at all — a torn-down cgroup
	_, ok := SampleWorkload(root)
	if ok {
		t.Fatal("expected ok=false for a missing cgroup directory")
	}
}

func TestSampleWorkloadEmptyPathReturnsFalse(t *testing.T) {
	_, ok := SampleWorkload("")
	if ok {
		t.Fatal("expected ok=false for an empty cgroup path")
	}
}
