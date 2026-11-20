// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// Workload is one container cgroup with its Kubernetes identity.
type Workload struct {
	Namespace    string
	Pod          string
	Container    string // container ID, shortened in labels
	WorkloadKind string
	WorkloadName string
	CgroupPath   string // absolute cgroup v2 directory
}

// Cgroups reads cgroup v2 CPU, memory, I/O and pressure per workload. The
// workload list comes from the agent's existing cgroup-to-pod attribution.
// By default each pod is charted once from its pod cgroup, whose v2 stats
// already include every container (and the pause container); Containers
// charts each container cgroup as well.
type Cgroups struct {
	List       func() []Workload
	Containers bool
	prev       map[string]cgPrev
}

// podLevel keeps one entry per pod: the pod cgroup when listed, otherwise
// the parent of a container cgroup when that parent is a pod cgroup.
func podLevel(ws []Workload) []Workload {
	type key struct{ ns, pod string }
	out := make([]Workload, 0, len(ws))
	idx := map[key]int{}
	for _, w := range ws {
		if w.Pod == "" {
			out = append(out, w)
			continue
		}
		if w.Container != "" {
			if parent := filepath.Dir(w.CgroupPath); strings.Contains(filepath.Base(parent), "pod") {
				w.Container, w.CgroupPath = "", parent
			}
		}
		k := key{w.Namespace, w.Pod}
		i, ok := idx[k]
		switch {
		case !ok:
			idx[k] = len(out)
			out = append(out, w)
		case out[i].Container != "" && w.Container == "":
			out[i] = w
		}
	}
	return out
}

type cgPrev struct {
	at          time.Time
	user, sys   float64
	seenRunOnce bool
}

func (*Cgroups) Info() Info { return Info{Name: "cgroups", Family: "cgroups"} }

func shortID(id string) string {
	if i := strings.LastIndex(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func (c *Cgroups) Collect(now time.Time, e *Emitter) error {
	if c.List == nil {
		return nil
	}
	if c.prev == nil {
		c.prev = map[string]cgPrev{}
	}
	seen := map[string]bool{}
	var errs int
	ws := c.List()
	if !c.Containers {
		ws = podLevel(ws)
	}
	for _, w := range ws {
		if w.CgroupPath == "" {
			continue
		}
		cpu, err := keyValueFile(filepath.Join(w.CgroupPath, "cpu.stat"))
		if err != nil {
			errs++
			continue
		}
		id := w.Namespace + "_" + w.Pod
		if w.Container != "" {
			id += "_" + shortID(w.Container)
		}
		seen[id] = true
		lbl := map[string]string{"namespace": w.Namespace, "pod": w.Pod}
		if w.Container != "" {
			lbl["container_id"] = shortID(w.Container)
		}
		if w.WorkloadKind != "" {
			lbl["workload_kind"] = w.WorkloadKind
			lbl["workload"] = w.WorkloadName
		}
		user, sys := cpu["user_usec"], cpu["system_usec"]
		if p, ok := c.prev[id]; ok {
			dt := now.Sub(p.at).Seconds()
			if dt > 0 && user >= p.user && sys >= p.sys {
				ch := Chart{Context: "cgroup.cpu", ID: "cgroup_" + id + ".cpu", Family: "cpu", Units: "%", Title: "Workload CPU usage (100% = 1 core)", Type: "stacked", Labels: lbl}
				e.Gauge(ch, "user", (user-p.user)/1e6/dt*100)
				e.Gauge(ch, "system", (sys-p.sys)/1e6/dt*100)
			}
		}
		c.prev[id] = cgPrev{at: now, user: user, sys: sys}
		th := Chart{Context: "cgroup.throttled", ID: "cgroup_" + id + ".throttled", Family: "cpu", Units: "periods/s", Title: "Workload CPU throttled periods", Labels: lbl}
		if np := cpu["nr_periods"]; np > 0 {
			e.Incremental(th, "throttled_periods", cpu["nr_throttled"], 1)
		}
		e.Incremental(Chart{Context: "cgroup.throttled_duration", ID: "cgroup_" + id + ".throttled_duration", Family: "cpu", Units: "ms", Title: "Workload CPU throttled time", Labels: lbl}, "duration", cpu["throttled_usec"], 0.001)

		if cur, ok := readFloat(filepath.Join(w.CgroupPath, "memory.current")); ok {
			const mib = 1 << 20
			e.Gauge(Chart{Context: "cgroup.mem_usage", ID: "cgroup_" + id + ".mem_usage", Family: "mem", Units: "MiB", Title: "Workload memory usage", Labels: lbl}, "ram", cur/mib)
			if mx, err := readTrim(filepath.Join(w.CgroupPath, "memory.max")); err == nil && mx != "max" {
				if lim := pf(mx); lim > 0 {
					e.Gauge(Chart{Context: "cgroup.mem_utilization", ID: "cgroup_" + id + ".mem_utilization", Family: "mem", Units: "%", Title: "Workload memory utilization of limit", Labels: lbl}, "utilization", cur/lim*100)
				}
			}
			if ms, err := keyValueFile(filepath.Join(w.CgroupPath, "memory.stat")); err == nil {
				m := Chart{Context: "cgroup.mem", ID: "cgroup_" + id + ".mem", Family: "mem", Units: "MiB", Title: "Workload memory breakdown", Type: "stacked", Labels: lbl}
				e.Gauge(m, "anon", ms["anon"]/mib)
				e.Gauge(m, "file", ms["file"]/mib)
				e.Gauge(m, "kernel", ms["kernel"]/mib)
				e.Gauge(m, "sock", ms["sock"]/mib)
				pg := Chart{Context: "cgroup.pgfaults", ID: "cgroup_" + id + ".pgfaults", Family: "mem", Units: "faults/s", Title: "Workload page faults", Labels: lbl}
				e.Incremental(pg, "faults", ms["pgfault"], 1)
				e.Incremental(pg, "major", ms["pgmajfault"], 1)
			}
		}
		if ev, err := keyValueFile(filepath.Join(w.CgroupPath, "memory.events")); err == nil {
			oe := Chart{Context: "cgroup.mem_events", ID: "cgroup_" + id + ".mem_events", Family: "mem", Units: "events/s", Title: "Workload memory events", Labels: lbl}
			e.Incremental(oe, "oom", ev["oom"], 1)
			e.Incremental(oe, "oom_kill", ev["oom_kill"], 1)
			e.Incremental(oe, "max", ev["max"], 1)
		}
		if lines, err := readLines(filepath.Join(w.CgroupPath, "io.stat")); err == nil {
			var rb, wb, rio, wio float64
			for _, l := range lines {
				for _, kv := range strings.Fields(l)[min(1, len(strings.Fields(l))):] {
					k, v, ok := strings.Cut(kv, "=")
					if !ok {
						continue
					}
					switch k {
					case "rbytes":
						rb += pf(v)
					case "wbytes":
						wb += pf(v)
					case "rios":
						rio += pf(v)
					case "wios":
						wio += pf(v)
					}
				}
			}
			io := Chart{Context: "cgroup.io", ID: "cgroup_" + id + ".io", Family: "disk", Units: "KiB/s", Title: "Workload I/O bandwidth", Labels: lbl}
			e.Incremental(io, "read", rb, 1.0/1024)
			e.Incremental(io, "write", wb, 1.0/1024)
			ops := Chart{Context: "cgroup.serviced_ops", ID: "cgroup_" + id + ".serviced_ops", Family: "disk", Units: "operations/s", Title: "Workload I/O operations", Labels: lbl}
			e.Incremental(ops, "read", rio, 1)
			e.Incremental(ops, "write", wio, 1)
		}
		plbl := copyWithout(lbl, "")
		plbl["chart_id"] = id
		for _, res := range []string{"cpu", "memory", "io"} {
			if lines, err := readLines(filepath.Join(w.CgroupPath, res+".pressure")); err == nil {
				emitPressure(e, "cgroup", res, plbl, lines)
			}
		}
	}
	for id := range c.prev {
		if !seen[id] {
			delete(c.prev, id)
		}
	}
	if len(seen) == 0 && errs > 0 {
		return errors.New("no workload cgroup was readable")
	}
	return nil
}
