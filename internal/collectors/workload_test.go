// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

func TestCgroupCollector(t *testing.T) {
	root := copyFixture(t, "cgroup")
	c := &Cgroups{Containers: true, List: func() []Workload {
		return []Workload{{Namespace: "shop", Pod: "web-1", Container: "containerd://0123456789abcdef", WorkloadKind: "Deployment", WorkloadName: "web", CgroupPath: filepath.Join(root, "pod1")}, {Namespace: "x", Pod: "gone", CgroupPath: filepath.Join(root, "missing")}}
	}}
	e := NewEmitter()
	t0 := time.Unix(5000, 0)
	e.Begin(t0)
	if err := c.Collect(t0, e); err != nil {
		t.Fatal(err)
	}
	f := index(e.Samples())
	f.want(t, "cgroup_shop_web-1_0123456789ab.mem_usage/ram", 100)
	f.want(t, "cgroup_shop_web-1_0123456789ab.mem_utilization/utilization", 50)
	f.want(t, "cgroup_shop_web-1_0123456789ab.mem/anon", 50)
	f.want(t, "cgroup.cpu_some_pressure_shop_web-1_0123456789ab/avg10", 5)
	if e.Samples()[0].Labels["workload"] != "web" || e.Samples()[0].Labels["container_id"] != "0123456789ab" {
		t.Fatalf("labels %v", e.Samples()[0].Labels)
	}

	rewrite(t, filepath.Join(root, "pod1", "cpu.stat"), "user_usec 2000000\nsystem_usec 1000000", "user_usec 2500000\nsystem_usec 1250000")
	rewrite(t, filepath.Join(root, "pod1", "io.stat"), "rbytes=1048576", "rbytes=2097152")
	t1 := t0.Add(time.Second)
	e.Begin(t1)
	_ = c.Collect(t1, e)
	f = index(e.Samples())
	f.want(t, "cgroup_shop_web-1_0123456789ab.cpu/user", 50)
	f.want(t, "cgroup_shop_web-1_0123456789ab.cpu/system", 25)
	f.want(t, "cgroup_shop_web-1_0123456789ab.io/read", 1024)
}

func TestProcessGroupsNeverReadsCmdline(t *testing.T) {
	root := copyFixture(t, "procs")
	// A cmdline/environ that exists must never be read: make them unreadable
	// so any attempt to read would also fail loudly in strace-style review.
	for _, pid := range []string{"100", "101", "200"} {
		for _, f := range []string{"cmdline", "environ"} {
			p := filepath.Join(root, pid, f)
			if err := os.WriteFile(p, []byte("--password=secret"), 0o000); err != nil {
				t.Fatal(err)
			}
		}
	}
	p := NewProcessGroups(Config{ProcRoot: root}, 1)
	e := NewEmitter()
	t0 := time.Unix(10, 0)
	e.Begin(t0)
	if err := p.Collect(t0, e); err != nil {
		t.Fatal(err)
	}
	f := index(e.Samples())
	f.want(t, "app.nginx: worker_processes/processes", 2)
	f.want(t, "app.nginx: worker_threads/threads", 3)
	f.want(t, "app.other_processes/processes", 1)
	for _, s := range e.Samples() {
		for _, v := range s.Labels {
			if v == "--password=secret" {
				t.Fatal("argument leaked into labels")
			}
		}
	}

	rewrite(t, filepath.Join(root, "100", "stat"), " 300 100 ", " 400 150 ")
	rewrite(t, filepath.Join(root, "100", "io"), "read_bytes: 1048576", "read_bytes: 3145728")
	t1 := t0.Add(2 * time.Second)
	e.Begin(t1)
	_ = p.Collect(t1, e)
	f = index(e.Samples())
	f.want(t, "app.nginx: worker_cpu_utilization/user", 50)
	f.want(t, "app.nginx: worker_cpu_utilization/system", 25)
	f.want(t, "app.nginx: worker_disk_io/reads", 1024)
}

func TestDatapathFromReport(t *testing.T) {
	r := &models.AgentReport{
		Stats:          []models.DestinationStat{{Packets: 100, Bytes: 1000, Blocked: 1}},
		InterfaceFlows: []models.InterfaceFlowStat{{Interface: "eth0", Direction: "ingress", Bytes: 500, Packets: 5}},
		KernelDrops:    []models.KernelDropStat{{ReasonName: "NO_SOCKET", Count: 10}},
		TCPEvents:      &models.TCPEventsSummary{Totals: models.TCPEventTotals{Retransmits: 3}},
	}
	d := &Datapath{Latest: func() *models.AgentReport { return r }}
	e := NewEmitter()
	e.Begin(time.Unix(1, 0))
	_ = d.Collect(time.Unix(1, 0), e)
	r = &models.AgentReport{
		Stats:          []models.DestinationStat{{Packets: 200, Bytes: 2000, Blocked: 3}},
		InterfaceFlows: []models.InterfaceFlowStat{{Interface: "eth0", Direction: "ingress", Bytes: 1500, Packets: 15}},
		KernelDrops:    []models.KernelDropStat{{ReasonName: "NO_SOCKET", Count: 14}},
		TCPEvents:      &models.TCPEventsSummary{Totals: models.TCPEventTotals{Retransmits: 5}},
	}
	e.Begin(time.Unix(2, 0))
	_ = d.Collect(time.Unix(2, 0), e)
	f := index(e.Samples())
	f.want(t, "ebpf.packets/observed", 100)
	f.want(t, "ebpf.packets/blocked", 2)
	f.want(t, "ebpf_iface_bandwidth.eth0/ingress", 8)
	f.want(t, "ebpf.kernel_drops/NO_SOCKET", 4)
	f.want(t, "ebpf.tcp_events/retransmits", 2)
}

func TestParseStatHandlesParensInComm(t *testing.T) {
	comm, f, ok := parseStat("42 (a (b) c) R 1 2 3")
	if !ok || comm != "a (b) c" || f[0] != "R" {
		t.Fatalf("got %q %v %v", comm, f, ok)
	}
}

func TestCgroupsChartEachPodOnce(t *testing.T) {
	const podDir = "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice"
	ws := podLevel([]Workload{
		{Namespace: "shop", Pod: "web-1", Container: "containerd://aaa", CgroupPath: podDir + "/cri-containerd-aaa.scope"},
		{Namespace: "shop", Pod: "web-1", Container: "containerd://pause", CgroupPath: podDir + "/cri-containerd-pause.scope"},
		{Namespace: "shop", Pod: "web-1", CgroupPath: podDir},
		{Namespace: "shop", Pod: "db-0", Container: "containerd://bbb", CgroupPath: "/sys/fs/cgroup/kubepods/podxyz/bbb"},
		{Namespace: "ops", Pod: "odd", Container: "containerd://ccc", CgroupPath: "/sys/fs/cgroup/custom/ccc"},
		{Pod: "", CgroupPath: "/sys/fs/cgroup/system.slice/x"},
	})
	if len(ws) != 4 {
		t.Fatalf("got %d entries, want one per pod plus the unattributed cgroup: %+v", len(ws), ws)
	}
	if ws[0].Pod != "web-1" || ws[0].Container != "" || ws[0].CgroupPath != podDir {
		t.Fatalf("web-1: %+v", ws[0])
	}
	if ws[1].Pod != "db-0" || ws[1].Container != "" || ws[1].CgroupPath != "/sys/fs/cgroup/kubepods/podxyz" {
		t.Fatalf("db-0 should use its pod cgroup: %+v", ws[1])
	}
	if ws[2].Pod != "odd" || ws[2].Container == "" {
		t.Fatalf("a container whose parent is not a pod cgroup stays container-level: %+v", ws[2])
	}
}
