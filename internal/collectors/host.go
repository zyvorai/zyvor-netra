// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config locates the host filesystems a collector reads.
type Config struct {
	ProcRoot string // default /proc
	SysRoot  string // default /sys
	// FSRoot prefixes mount points before statfs, for example /proc/1/root
	// when the agent runs in its own mount namespace with hostPID.
	FSRoot string
}

func (c Config) fs() fsys {
	f := fsys{proc: c.ProcRoot, sys: c.SysRoot}
	if f.proc == "" {
		f.proc = "/proc"
	}
	if f.sys == "" {
		f.sys = "/sys"
	}
	return f
}

// Host returns the host and network collectors.
func Host(cfg Config) []Collector {
	f := cfg.fs()
	return []Collector{
		&CPU{fs: f},
		&Memory{fs: f},
		&Pressure{fs: f},
		&Disks{fs: f},
		&Filesystems{fs: f, root: cfg.FSRoot},
		&System{fs: f},
		&NetDev{fs: f},
		&SNMP{fs: f},
		&Netstat{fs: f},
		&Sockstat{fs: f},
		&Conntrack{fs: f},
		&Softnet{fs: f},
	}
}

// ---------------------------------------------------------------- CPU

var cpuDims = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"}

// CPU reads /proc/stat and /proc/softirqs.
type CPU struct {
	fs   fsys
	prev map[string][]float64
}

func (*CPU) Info() Info { return Info{Name: "proc.stat", Family: "cpu"} }

func (c *CPU) Collect(_ time.Time, e *Emitter) error {
	lines, err := readLines(c.fs.procPath("stat"))
	if err != nil {
		return err
	}
	if c.prev == nil {
		c.prev = map[string][]float64{}
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch {
		case f[0] == "cpu" || strings.HasPrefix(f[0], "cpu"):
			vals := make([]float64, len(cpuDims))
			for i := range cpuDims {
				if i+1 < len(f) {
					vals[i] = pf(f[i+1])
				}
			}
			// guest time is already included in user and nice.
			vals[0] -= vals[8]
			vals[1] -= vals[9]
			prev := c.prev[f[0]]
			c.prev[f[0]] = vals
			if prev == nil {
				continue
			}
			var total float64
			deltas := make([]float64, len(vals))
			for i := range vals {
				deltas[i] = max(vals[i]-prev[i], 0)
				total += deltas[i]
			}
			if total <= 0 {
				continue
			}
			ch := Chart{Context: "system.cpu", ID: "system.cpu", Family: "cpu", Units: "%", Title: "Total CPU utilization", Type: "stacked"}
			if f[0] != "cpu" {
				core := strings.TrimPrefix(f[0], "cpu")
				ch = Chart{Context: "cpu.cpu", ID: "cpu.cpu" + core, Family: "cpu", Units: "%", Title: "Core utilization", Type: "stacked", Labels: map[string]string{"cpu": core}}
			}
			for i, d := range cpuDims {
				if d == "idle" {
					continue
				}
				e.Gauge(ch, d, deltas[i]/total*100)
			}
		case f[0] == "intr":
			e.Incremental(Chart{Context: "system.intr", Family: "cpu", Units: "interrupts/s", Title: "CPU interrupts"}, "interrupts", pf(f[1]), 1)
		case f[0] == "ctxt":
			e.Incremental(Chart{Context: "system.ctxt", Family: "cpu", Units: "context switches/s", Title: "CPU context switches"}, "switches", pf(f[1]), 1)
		case f[0] == "processes":
			e.Incremental(Chart{Context: "system.forks", Family: "processes", Units: "processes/s", Title: "Started processes"}, "started", pf(f[1]), 1)
		case f[0] == "procs_running":
			e.Gauge(Chart{Context: "system.processes", Family: "processes", Units: "processes", Title: "System processes"}, "running", pf(f[1]))
		case f[0] == "procs_blocked":
			e.Gauge(Chart{Context: "system.processes", Family: "processes", Units: "processes", Title: "System processes"}, "blocked", pf(f[1]))
		}
	}
	// Per-type softirq totals across CPUs.
	if sl, err := readLines(c.fs.procPath("softirqs")); err == nil {
		ch := Chart{Context: "system.softirqs", Family: "cpu", Units: "softirqs/s", Title: "System softirqs", Type: "stacked"}
		for _, l := range sl[min(1, len(sl)):] {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			var sum float64
			for _, v := range f[1:] {
				sum += pf(v)
			}
			e.Incremental(ch, strings.ToLower(strings.TrimSuffix(f[0], ":")), sum, 1)
		}
	}
	return nil
}

// ---------------------------------------------------------------- Memory

// Memory reads /proc/meminfo and /proc/vmstat.
type Memory struct{ fs fsys }

func (*Memory) Info() Info { return Info{Name: "proc.meminfo", Family: "mem"} }

func (m *Memory) Collect(_ time.Time, e *Emitter) error {
	mi, err := keyValueFile(m.fs.procPath("meminfo"))
	if err != nil {
		return err
	}
	const mib = 1.0 / 1024 // meminfo values are KiB
	total, free := mi["MemTotal"], mi["MemFree"]
	buffers, cached := mi["Buffers"], mi["Cached"]+mi["SReclaimable"]-mi["Shmem"]
	used := total - free - buffers - cached
	ram := Chart{Context: "system.ram", Family: "ram", Units: "MiB", Title: "System RAM", Type: "stacked"}
	e.Gauge(ram, "free", free*mib)
	e.Gauge(ram, "used", max(used, 0)*mib)
	e.Gauge(ram, "cached", max(cached, 0)*mib)
	e.Gauge(ram, "buffers", buffers*mib)
	if v, ok := mi["MemAvailable"]; ok {
		e.Gauge(Chart{Context: "mem.available", Family: "ram", Units: "MiB", Title: "Available RAM"}, "avail", v*mib)
		if total > 0 {
			e.Gauge(Chart{Context: "mem.used_percent", Family: "ram", Units: "%", Title: "RAM used (excluding reclaimable)"}, "used", (total-v)/total*100)
		}
	}
	if st := mi["SwapTotal"]; st > 0 {
		sw := Chart{Context: "mem.swap", Family: "swap", Units: "MiB", Title: "System swap", Type: "stacked"}
		e.Gauge(sw, "free", mi["SwapFree"]*mib)
		e.Gauge(sw, "used", (st-mi["SwapFree"])*mib)
	}
	e.Gauge(Chart{Context: "mem.committed", Family: "ram", Units: "MiB", Title: "Committed memory"}, "committed_as", mi["Committed_AS"]*mib)
	k := Chart{Context: "mem.kernel", Family: "kernel", Units: "MiB", Title: "Memory used by the kernel", Type: "stacked"}
	e.Gauge(k, "slab", mi["Slab"]*mib)
	e.Gauge(k, "kernel_stack", mi["KernelStack"]*mib)
	e.Gauge(k, "page_tables", mi["PageTables"]*mib)
	e.Gauge(k, "vmalloc_used", mi["VmallocUsed"]*mib)
	wb := Chart{Context: "mem.writeback", Family: "kernel", Units: "MiB", Title: "Writeback memory"}
	e.Gauge(wb, "dirty", mi["Dirty"]*mib)
	e.Gauge(wb, "writeback", mi["Writeback"]*mib)
	if hp := mi["HugePages_Total"]; hp > 0 {
		h := Chart{Context: "mem.hugepages", Family: "hugepages", Units: "pages", Title: "Huge pages", Type: "stacked"}
		e.Gauge(h, "free", mi["HugePages_Free"])
		e.Gauge(h, "used", hp-mi["HugePages_Free"])
	}

	vm, err := keyValueFile(m.fs.procPath("vmstat"))
	if err != nil {
		return nil
	}
	pg := Chart{Context: "mem.pgfaults", Family: "ram", Units: "faults/s", Title: "Memory page faults"}
	e.Incremental(pg, "minor", vm["pgfault"]-vm["pgmajfault"], 1)
	e.Incremental(pg, "major", vm["pgmajfault"], 1)
	io := Chart{Context: "system.pgpgio", Family: "disk", Units: "KiB/s", Title: "Memory paged from/to disk"}
	e.Incremental(io, "in", vm["pgpgin"], 1)
	e.Incremental(io, "out", vm["pgpgout"], 1)
	sio := Chart{Context: "mem.swapio", Family: "swap", Units: "KiB/s", Title: "Swap I/O"}
	e.Incremental(sio, "in", vm["pswpin"], 4)
	e.Incremental(sio, "out", vm["pswpout"], 4)
	if v, ok := vm["oom_kill"]; ok {
		e.Incremental(Chart{Context: "mem.oom_kill", Family: "ram", Units: "kills/s", Title: "Out of memory kills"}, "kills", v, 1)
	}
	return nil
}

// ---------------------------------------------------------------- Pressure

// Pressure reads pressure stall information from /proc/pressure.
type Pressure struct{ fs fsys }

func (*Pressure) Info() Info { return Info{Name: "proc.pressure", Family: "pressure"} }

func (p *Pressure) Collect(_ time.Time, e *Emitter) error {
	found := false
	for _, res := range []string{"cpu", "memory", "io"} {
		lines, err := readLines(p.fs.procPath("pressure", res))
		if err != nil {
			continue
		}
		found = true
		emitPressure(e, "system", res, nil, lines)
	}
	if !found {
		return errors.New("pressure stall information not available")
	}
	return nil
}

// emitPressure writes the some/full avg10/60/300 gauges and the stall time
// rate for one resource. prefix is "system" or "cgroup".
func emitPressure(e *Emitter, prefix, res string, labels map[string]string, lines []string) {
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		kind := f[0] // some | full
		id := ""
		if labels != nil {
			id = "_" + labels["chart_id"]
		}
		lbl := labels
		if lbl != nil {
			lbl = copyWithout(labels, "chart_id")
		}
		ch := Chart{Context: fmt.Sprintf("%s.%s_%s_pressure", prefix, res, kind), ID: fmt.Sprintf("%s.%s_%s_pressure%s", prefix, res, kind, id), Family: "pressure", Units: "%", Title: strings.ToUpper(res[:1]) + res[1:] + " " + kind + " pressure", Labels: lbl}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch k {
			case "avg10", "avg60", "avg300":
				e.Gauge(ch, k, pf(v))
			case "total":
				st := Chart{Context: fmt.Sprintf("%s.%s_%s_pressure_stall_time", prefix, res, kind), ID: fmt.Sprintf("%s.%s_%s_pressure_stall_time%s", prefix, res, kind, id), Family: "pressure", Units: "ms", Title: strings.ToUpper(res[:1]) + res[1:] + " " + kind + " stall time", Labels: lbl}
				e.Incremental(st, "time", pf(v), 0.001) // total is microseconds
			}
		}
	}
}

func copyWithout(m map[string]string, drop string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if k != drop {
			out[k] = v
		}
	}
	return out
}

// ---------------------------------------------------------------- Disks

// Disks reads /proc/diskstats for whole block devices.
type Disks struct {
	fs   fsys
	prev map[string]diskPrev
}

type diskPrev struct {
	at                   time.Time
	ios, ticks, weighted float64
}

func (*Disks) Info() Info { return Info{Name: "proc.diskstats", Family: "disk"} }

func (d *Disks) Collect(now time.Time, e *Emitter) error {
	lines, err := readLines(d.fs.procPath("diskstats"))
	if err != nil {
		return err
	}
	if d.prev == nil {
		d.prev = map[string]diskPrev{}
	}
	var totalR, totalW float64
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 14 {
			continue
		}
		dev := f[2]
		if strings.HasPrefix(dev, "ram") || strings.HasPrefix(dev, "loop") || strings.HasPrefix(dev, "zram") {
			continue
		}
		if _, err := os.Stat(d.fs.sysPath("block", dev)); err != nil {
			continue // partition or not a block device on this host
		}
		reads, readSect, readMs := pf(f[3]), pf(f[5]), pf(f[6])
		writes, writeSect, writeMs := pf(f[7]), pf(f[9]), pf(f[10])
		inflight, ioMs, weightedMs := pf(f[11]), pf(f[12]), pf(f[13])
		lbl := map[string]string{"device": dev}
		io := Chart{Context: "disk.io", ID: "disk.io_" + dev, Family: "disk", Units: "KiB/s", Title: "Disk I/O bandwidth", Labels: lbl}
		e.Incremental(io, "reads", readSect, 0.5)
		e.Incremental(io, "writes", writeSect, 0.5)
		ops := Chart{Context: "disk.ops", ID: "disk.ops_" + dev, Family: "disk", Units: "operations/s", Title: "Disk completed I/O operations", Labels: lbl}
		e.Incremental(ops, "reads", reads, 1)
		e.Incremental(ops, "writes", writes, 1)
		e.Gauge(Chart{Context: "disk.qops", ID: "disk.qops_" + dev, Family: "disk", Units: "operations", Title: "Disk current I/O operations", Labels: lbl}, "operations", inflight)
		ios := reads + writes
		if p, ok := d.prev[dev]; ok {
			dt := now.Sub(p.at).Seconds() * 1000
			if dt > 0 && ioMs >= p.ticks {
				e.Gauge(Chart{Context: "disk.util", ID: "disk.util_" + dev, Family: "disk", Units: "%", Title: "Disk utilization time", Labels: lbl}, "utilization", min((ioMs-p.ticks)/dt*100, 100))
				e.Gauge(Chart{Context: "disk.backlog", ID: "disk.backlog_" + dev, Family: "disk", Units: "milliseconds", Title: "Disk backlog", Labels: lbl}, "backlog", max(weightedMs-p.weighted, 0)/dt*1000)
			}
			if dio := ios - p.ios; dio > 0 {
				e.Gauge(Chart{Context: "disk.await", ID: "disk.await_" + dev, Family: "disk", Units: "milliseconds/operation", Title: "Average completed I/O operation time", Labels: lbl}, "await", max(weightedMs-p.weighted, 0)/dio)
			}
		}
		_ = readMs
		_ = writeMs
		d.prev[dev] = diskPrev{at: now, ios: ios, ticks: ioMs, weighted: weightedMs}
		totalR += readSect
		totalW += writeSect
	}
	sys := Chart{Context: "system.io", Family: "disk", Units: "KiB/s", Title: "Disk I/O"}
	e.Incremental(sys, "in", totalR, 0.5)
	e.Incremental(sys, "out", totalW, 0.5)
	return nil
}

// ---------------------------------------------------------------- System

// System reads load average, uptime, entropy and file handles.
type System struct{ fs fsys }

func (*System) Info() Info { return Info{Name: "proc.system", Family: "system"} }

func (s *System) Collect(_ time.Time, e *Emitter) error {
	la, err := readTrim(s.fs.procPath("loadavg"))
	if err != nil {
		return err
	}
	if f := strings.Fields(la); len(f) >= 3 {
		ch := Chart{Context: "system.load", Family: "load", Units: "load", Title: "System load average"}
		e.Gauge(ch, "load1", pf(f[0]))
		e.Gauge(ch, "load5", pf(f[1]))
		e.Gauge(ch, "load15", pf(f[2]))
	}
	if up, err := readTrim(s.fs.procPath("uptime")); err == nil {
		if f := strings.Fields(up); len(f) > 0 {
			e.Gauge(Chart{Context: "system.uptime", Family: "uptime", Units: "seconds", Title: "System uptime"}, "uptime", pf(f[0]))
		}
	}
	if v, ok := readFloat(s.fs.procPath("sys", "kernel", "random", "entropy_avail")); ok {
		e.Gauge(Chart{Context: "system.entropy", Family: "entropy", Units: "entropy", Title: "Available entropy"}, "entropy", v)
	}
	if fnr, err := readTrim(s.fs.procPath("sys", "fs", "file-nr")); err == nil {
		if f := strings.Fields(fnr); len(f) >= 3 {
			ch := Chart{Context: "system.file_nr_used", Family: "files", Units: "files", Title: "File descriptors"}
			e.Gauge(ch, "used", pf(f[0])-pf(f[1]))
			if mx := pf(f[2]); mx > 0 {
				e.Gauge(Chart{Context: "system.file_nr_utilization", Family: "files", Units: "%", Title: "File descriptor utilization"}, "used", (pf(f[0])-pf(f[1]))/mx*100)
			}
		}
	}
	return nil
}
