// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build linux

package agent

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/zyvorai/netra/internal/histograms"
	"github.com/zyvorai/netra/internal/models"
)

// bpfStatsRunTime is BPF_STATS_RUN_TIME from linux/bpf.h.
const bpfStatsRunTime = 0

func (a *Agent) enableProgStats() {
	closer, err := ebpf.EnableStats(bpfStatsRunTime)
	if err != nil {
		a.log.Info("BPF program run stats unavailable", "error", err)
		return
	}
	a.progStats = closer
}

func (a *Agent) readProgramHealth() []models.BPFProgramStat {
	if a.collection == nil {
		return nil
	}
	names := make([]string, 0, len(a.collection.Programs))
	for name := range a.collection.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	programs := make(map[string]*ebpf.Program, len(names)+1)
	for _, name := range names {
		programs[name] = a.collection.Programs[name]
	}
	// Node isolation is its own collection; report it beside the datapath.
	if a.nodeIso != nil {
		if p := a.nodeIso.Program(); p != nil {
			names = append(names, "netra_nodeiso_egress")
			programs["netra_nodeiso_egress"] = p
		}
	}
	out := make([]models.BPFProgramStat, 0, len(names))
	for _, name := range names {
		p := programs[name]
		st := models.BPFProgramStat{Name: name, Attached: a.attachedProgs[name]}
		if info, err := p.Info(); err == nil {
			if id, ok := info.ID(); ok {
				st.ID = uint32(id)
			}
			st.Type = info.Type.String()
		} else {
			st.InfoError = err.Error()
		}
		if stats, err := p.Stats(); err == nil {
			st.RunCount = stats.RunCount
			st.RunTimeNS = uint64(stats.Runtime)
			st.RecursionMisses = stats.RecursionMisses
		}
		out = append(out, st)
	}
	return out
}

func (a *Agent) readHostHistogramCounters() histograms.HostCounters {
	var out histograms.HostCounters
	out.ListenOverflows, out.ListenDrops = readTCPListenCounters()
	out.SoftirqNETRX = readSoftirqNETRX()
	return out
}

func readTCPListenCounters() (overflows, drops uint64) {
	f, err := os.Open("/proc/net/netstat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var headers, values []string
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "TcpExt:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if headers == nil {
			headers = fields[1:]
			continue
		}
		values = fields[1:]
		break
	}
	if len(headers) == 0 || len(headers) != len(values) {
		return 0, 0
	}
	for i, h := range headers {
		v, _ := strconv.ParseUint(values[i], 10, 64)
		switch h {
		case "ListenOverflows":
			overflows = v
		case "ListenDrops":
			drops = v
		}
	}
	return overflows, drops
}

func readSoftirqNETRX() uint64 {
	b, err := os.ReadFile("/proc/softirqs")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "NET_RX:") {
			continue
		}
		fields := strings.Fields(line)
		var sum uint64
		for _, f := range fields[1:] {
			v, _ := strconv.ParseUint(f, 10, 64)
			sum += v
		}
		return sum
	}
	return 0
}

// markAttached records that a loaded BPF program was successfully attached.
func (a *Agent) markAttached(prog string) {
	if a.attachedProgs == nil {
		a.attachedProgs = map[string]bool{}
	}
	a.attachedProgs[prog] = true
}
