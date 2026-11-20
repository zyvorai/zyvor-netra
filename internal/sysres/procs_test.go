// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package sysres

import (
	"path/filepath"
	"testing"
)

func TestSampleProcessesAndRank(t *testing.T) {
	root := t.TempDir()
	// utime is field 14 (index 11 after ')'), stime field 15.
	mustWrite(t, filepath.Join(root, "proc/10/stat"), "10 (nginx) R 1 1 1 0 -1 0 0 0 0 0 200 10 0 0 20 0 1 0 0 0 100\n")
	mustWrite(t, filepath.Join(root, "proc/10/status"), "Name:\tnginx\nVmRSS:\t  1024 kB\n")
	mustWrite(t, filepath.Join(root, "proc/11/stat"), "11 (kube proxy) S 1 1 1 0 -1 0 0 0 0 0 10 0 0 0 20 0 1 0 0 0 50\n")
	mustWrite(t, filepath.Join(root, "proc/11/status"), "Name:\tkube proxy\nVmRSS:\t  8192 kB\n")
	mustWrite(t, filepath.Join(root, "proc/not-a-pid/stat"), "skip\n")

	got := SampleProcesses(root)
	if len(got) != 2 {
		t.Fatalf("samples=%d %+v", len(got), got)
	}
	byPID := map[uint32]ProcSample{}
	for _, p := range got {
		byPID[p.PID] = p
	}
	if byPID[10].Comm != "nginx" || byPID[10].Jiffies != 210 || byPID[10].RSSBytes != 1024*1024 {
		t.Fatalf("pid 10: %+v", byPID[10])
	}
	if byPID[11].Comm != "kube proxy" || byPID[11].RSSBytes != 8192*1024 {
		t.Fatalf("pid 11: %+v", byPID[11])
	}

	prev := map[uint32]uint64{10: 110, 11: 10}
	byCPU, byRSS, next := TopHostProcesses(prev, got, 1)
	if len(byCPU) != 2 || byCPU[0].PID != 10 || byCPU[0].CPUPercent != 100 {
		t.Fatalf("by cpu: %+v", byCPU)
	}
	if byRSS[0].PID != 11 {
		t.Fatalf("by rss: %+v", byRSS)
	}
	if next[10] != 210 || next[11] != byPID[11].Jiffies {
		t.Fatalf("next: %+v", next)
	}

	// First tick: no previous sample, CPU stays 0, memory ranking still works.
	byCPU, byRSS, _ = TopHostProcesses(nil, got, 0)
	if byCPU[0].CPUPercent != 0 || byRSS[0].PID != 11 {
		t.Fatalf("first tick cpu=%+v rss=%+v", byCPU, byRSS)
	}
}

func TestSampleProcessesMissingProc(t *testing.T) {
	if got := SampleProcesses(t.TempDir()); got != nil {
		t.Fatalf("got %+v", got)
	}
}
