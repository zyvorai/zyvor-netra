// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// clockTicks is USER_HZ, which is 100 on every mainstream Linux build.
const clockTicks = 100.0

// ProcessGroups aggregates per-process CPU, memory, threads, I/O and page
// faults by comm, the 15-byte kernel task name. It reads /proc/<pid>/stat,
// statm and io only. It never opens cmdline, environ or any file that holds
// arguments or environment.
type ProcessGroups struct {
	fs   fsys
	Max  int // groups kept as separate charts; the rest fold into "other"
	prev map[int]procPrev
	keep map[string]bool
}

type procPrev struct {
	start                 string
	at                    time.Time
	utime, stime          float64
	minflt, majflt        float64
	readBytes, writeBytes float64
}

type procGroup struct {
	user, sys         float64 // percent
	rssMiB            float64
	procs, threads    float64
	readKiB, writeKiB float64
	minflt, majflt    float64
}

// NewProcessGroups returns the process-group collector.
func NewProcessGroups(cfg Config, maxGroups int) *ProcessGroups {
	if maxGroups <= 0 {
		maxGroups = 40
	}
	return &ProcessGroups{fs: cfg.fs(), Max: maxGroups}
}

func (*ProcessGroups) Info() Info {
	return Info{Name: "apps.groups", Family: "apps", Every: 2 * time.Second}
}

// parseStat returns comm and the fields after it from /proc/<pid>/stat.
func parseStat(s string) (string, []string, bool) {
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return "", nil, false
	}
	return s[open+1 : end], strings.Fields(s[end+1:]), true
}

func (p *ProcessGroups) Collect(now time.Time, e *Emitter) error {
	entries, err := os.ReadDir(p.fs.proc)
	if err != nil {
		return err
	}
	if p.prev == nil {
		p.prev = map[int]procPrev{}
	}
	pageMiB := float64(os.Getpagesize()) / (1 << 20)
	groups := map[string]*procGroup{}
	seen := map[int]bool{}
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(p.fs.procPath(ent.Name(), "stat"))
		if err != nil {
			continue
		}
		comm, f, ok := parseStat(string(raw))
		// f[0] is field 3 (state); field N is f[N-3].
		if !ok || len(f) < 22 {
			continue
		}
		if f[0] == "Z" {
			continue
		}
		g := groups[comm]
		if g == nil {
			g = &procGroup{}
			groups[comm] = g
		}
		g.procs++
		g.threads += pf(f[17])
		g.rssMiB += pf(f[21]) * pageMiB
		cur := procPrev{start: f[19], at: now, utime: pf(f[11]), stime: pf(f[12]), minflt: pf(f[7]), majflt: pf(f[9])}
		if io, err := keyValueFile(p.fs.procPath(ent.Name(), "io")); err == nil {
			cur.readBytes, cur.writeBytes = io["read_bytes"], io["write_bytes"]
		}
		seen[pid] = true
		if old, ok := p.prev[pid]; ok && old.start == cur.start {
			if dt := now.Sub(old.at).Seconds(); dt > 0 {
				g.user += max(cur.utime-old.utime, 0) / clockTicks / dt * 100
				g.sys += max(cur.stime-old.stime, 0) / clockTicks / dt * 100
				g.minflt += max(cur.minflt-old.minflt, 0) / dt
				g.majflt += max(cur.majflt-old.majflt, 0) / dt
				g.readKiB += max(cur.readBytes-old.readBytes, 0) / 1024 / dt
				g.writeKiB += max(cur.writeBytes-old.writeBytes, 0) / 1024 / dt
			}
		}
		p.prev[pid] = cur
	}
	for pid := range p.prev {
		if !seen[pid] {
			delete(p.prev, pid)
		}
	}
	// Keep the set of separately charted groups sticky so series do not churn:
	// a group, once chosen, stays until it disappears.
	if p.keep == nil {
		p.keep = map[string]bool{}
	}
	for name := range p.keep {
		if groups[name] == nil {
			delete(p.keep, name)
		}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := groups[names[i]], groups[names[j]]
		if sa, sb := a.user+a.sys+a.rssMiB/64, b.user+b.sys+b.rssMiB/64; sa != sb {
			return sa > sb
		}
		if a.procs != b.procs {
			return a.procs > b.procs
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		if len(p.keep) >= p.Max {
			break
		}
		p.keep[name] = true
	}
	other := &procGroup{}
	for name, g := range groups {
		if p.keep[name] {
			emitGroup(e, name, g)
			continue
		}
		other.user += g.user
		other.sys += g.sys
		other.rssMiB += g.rssMiB
		other.procs += g.procs
		other.threads += g.threads
		other.readKiB += g.readKiB
		other.writeKiB += g.writeKiB
		other.minflt += g.minflt
		other.majflt += g.majflt
	}
	if other.procs > 0 {
		emitGroup(e, "other", other)
	}
	return nil
}

func emitGroup(e *Emitter, name string, g *procGroup) {
	lbl := map[string]string{"app_group": name}
	id := "app." + name
	cpu := Chart{Context: "app.cpu_utilization", ID: id + "_cpu_utilization", Family: "cpu", Units: "%", Title: "Process group CPU (100% = 1 core)", Type: "stacked", Labels: lbl}
	e.Gauge(cpu, "user", g.user)
	e.Gauge(cpu, "system", g.sys)
	e.Gauge(Chart{Context: "app.mem_usage", ID: id + "_mem_usage", Family: "mem", Units: "MiB", Title: "Process group resident memory", Labels: lbl}, "rss", g.rssMiB)
	e.Gauge(Chart{Context: "app.processes", ID: id + "_processes", Family: "processes", Units: "processes", Title: "Process group processes", Labels: lbl}, "processes", g.procs)
	e.Gauge(Chart{Context: "app.threads", ID: id + "_threads", Family: "processes", Units: "threads", Title: "Process group threads", Labels: lbl}, "threads", g.threads)
	io := Chart{Context: "app.disk_io", ID: id + "_disk_io", Family: "disk", Units: "KiB/s", Title: "Process group disk I/O", Labels: lbl}
	e.Gauge(io, "reads", g.readKiB)
	e.Gauge(io, "writes", g.writeKiB)
	pf := Chart{Context: "app.page_faults", ID: id + "_page_faults", Family: "mem", Units: "faults/s", Title: "Process group page faults", Labels: lbl}
	e.Gauge(pf, "minor", g.minflt)
	e.Gauge(pf, "major", g.majflt)
}
