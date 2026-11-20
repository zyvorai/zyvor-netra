// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package alert

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/notify"
)

func TestBuildDropContext(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	ev := notify.Event{
		Source: "dropdiag", Kind: "softnet-drop", Severity: "critical",
		Subject: "node-1", Message: "softnet drops", Value: 1200, Node: "node-1",
		Timestamp: now,
	}
	agent := models.AgentStatus{
		AgentReport: models.AgentReport{
			Node: "node-1",
			NodeResources: models.NodeResourceSnapshot{
				Host: models.HostResourceSnapshot{
					Hostname: "worker-1", KernelRelease: "6.8.0",
					CPUCores: 4, CPUPercent: 400, // 100% of 4 cores → hot (>= 320)
					MemoryTotalBytes: 1000, MemoryUsedBytes: 950,
					LoadAvg1: 6,
				},
				Workloads: []models.WorkloadResourceStat{
					{Pod: "quiet", CPUPercent: 1, MemoryUsedBytes: 10},
					{Pod: "mem-hog", CPUPercent: 5, MemoryUsedBytes: 900},
					{Pod: "cpu-hog", CPUPercent: 80, MemoryUsedBytes: 20},
				},
			},
			PolicyDrops: []models.PolicyDropStat{
				{Packets: 3, Comm: "other", PID: 9, AttributionState: "attributed"},
				{Packets: 40, Comm: "nginx", PID: 42, Pod: "web", AttributionState: "attributed"},
			},
			HostProcesses: models.HostProcessTops{
				ByCPU:    []models.HostProcessStat{{PID: 7, Comm: "ksoftirqd", CPUPercent: 90, RSSBytes: 0}},
				ByMemory: []models.HostProcessStat{{PID: 8, Comm: "java", CPUPercent: 2, RSSBytes: 1 << 30}},
			},
			Stack: models.NodeStackStat{SoftnetDropped: 1500},
			QdiscStats: []models.QdiscStat{
				{Interface: "eth0", Kind: "fq_codel", Drops: 4},
				{Interface: "eth1", Kind: "mq", Drops: 20},
			},
			KernelDrops: []models.KernelDropStat{
				{Reason: 2, Count: 9},
				{Reason: 99, Count: 1},
			},
		},
		AgeSeconds: 2,
	}

	got := BuildDropContext(now, ev, agent)
	if got.Node.Name != "node-1" || got.Node.Hostname != "worker-1" || got.Node.KernelRelease != "6.8.0" {
		t.Fatalf("node: %+v", got.Node)
	}
	if !got.CPUHot || !got.MemoryHot {
		t.Fatalf("pressure cpu=%v mem=%v", got.CPUHot, got.MemoryHot)
	}
	if len(got.TopWorkloadsByCPU) == 0 || got.TopWorkloadsByCPU[0].Pod != "cpu-hog" {
		t.Fatalf("top cpu workload: %+v", got.TopWorkloadsByCPU)
	}
	if len(got.TopWorkloadsByMemory) == 0 || got.TopWorkloadsByMemory[0].Pod != "mem-hog" {
		t.Fatalf("top memory workload: %+v", got.TopWorkloadsByMemory)
	}
	if len(got.PolicyDropProcesses) == 0 || got.PolicyDropProcesses[0].Comm != "nginx" || got.PolicyDropProcesses[0].PID != 42 {
		t.Fatalf("policy process: %+v", got.PolicyDropProcesses)
	}
	if len(got.TopProcessesByCPU) != 1 || got.TopProcessesByCPU[0].Comm != "ksoftirqd" {
		t.Fatalf("host cpu: %+v", got.TopProcessesByCPU)
	}
	if len(got.TopProcessesByMemory) != 1 || got.TopProcessesByMemory[0].Comm != "java" {
		t.Fatalf("host mem: %+v", got.TopProcessesByMemory)
	}
	if got.Stack.SoftnetDropped != 1500 {
		t.Fatalf("stack: %+v", got.Stack)
	}
	if got.QdiscStats[0].Interface != "eth1" {
		t.Fatalf("qdisc: %+v", got.QdiscStats)
	}
	if got.KernelDrops[0].ReasonName != "no-socket" {
		t.Fatalf("kernel reason: %+v", got.KernelDrops[0])
	}
	if got.KernelDrops[1].ReasonName != "reason #99" {
		t.Fatalf("unknown reason: %+v", got.KernelDrops[1])
	}

	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	for _, forbidden := range []string{`"cmdline"`, `"argv"`, `"environ"`} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("context JSON contains %q", forbidden)
		}
	}
}

func TestHostPressureThresholds(t *testing.T) {
	cpu, mem := hostPressure(models.HostResourceSnapshot{CPUCores: 2, CPUPercent: 159, MemoryTotalBytes: 100, MemoryUsedBytes: 89})
	if cpu || mem {
		t.Fatalf("below threshold: cpu=%v mem=%v", cpu, mem)
	}
	cpu, mem = hostPressure(models.HostResourceSnapshot{CPUCores: 0, CPUPercent: 100, MemoryTotalBytes: 0, MemoryUsedBytes: 10})
	if cpu || mem {
		t.Fatalf("zero capacity must not be hot: cpu=%v mem=%v", cpu, mem)
	}
}
