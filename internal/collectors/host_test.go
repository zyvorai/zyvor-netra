// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/tsdb"
)

// copyFixture copies testdata/<name> into a temp dir so tests can mutate
// counters between runs.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", name)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func rewrite(t *testing.T, path, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s does not contain %q", path, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, new, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

type found map[string]float64

func index(samples []tsdb.Sample) found {
	out := found{}
	for _, s := range samples {
		out[s.Chart+"/"+s.Dimension] = s.V
	}
	return out
}

func (f found) want(t *testing.T, key string, v float64) {
	t.Helper()
	got, ok := f[key]
	if !ok {
		t.Fatalf("missing %s", key)
	}
	if math.Abs(got-v) > 1e-6*math.Max(1, math.Abs(v)) {
		t.Fatalf("%s = %v, want %v", key, got, v)
	}
}

func runAll(cs []Collector, ems []*Emitter, now time.Time) found {
	var all []tsdb.Sample
	for i, c := range cs {
		ems[i].Begin(now)
		_ = c.Collect(now, ems[i])
		ems[i].End()
		all = append(all, ems[i].Samples()...)
	}
	return index(all)
}

func TestHostCollectorsFromFixtures(t *testing.T) {
	root := copyFixture(t, "host")
	proc, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	statfs = func(path string) (fsUsage, error) {
		return fsUsage{BlockSize: 4096, Blocks: 1 << 20, Free: 1 << 19, Avail: 1<<19 - 1000, Inodes: 1000, InodesFree: 250}, nil
	}
	t.Cleanup(func() { statfs = platformStatfs })
	cs := Host(Config{ProcRoot: proc, SysRoot: sys})
	ems := make([]*Emitter, len(cs))
	for i := range ems {
		ems[i] = NewEmitter()
	}
	t0 := time.Unix(1_700_000_000, 0)
	first := runAll(cs, ems, t0)

	first.want(t, "system.ram/free", 4000)
	first.want(t, "mem.available/avail", 8000)
	first.want(t, "mem.swap/used", 1000)
	first.want(t, "system.load/load1", 0.5)
	first.want(t, "system.processes/running", 3)
	first.want(t, "system.cpu_some_pressure/avg10", 1.5)
	first.want(t, "system.io_full_pressure/avg60", 0.5)
	first.want(t, "ipv4.tcpsock/connections", 42)
	first.want(t, "ipv4.sockstat_tcp_sockets/tw", 10)
	first.want(t, "ipv4.sockstat_tcp_mem/mem", 80)
	first.want(t, "netfilter.conntrack_utilization/used", 90)
	first.want(t, "net_speed.eth0/speed", 10_000_000)
	first.want(t, "net_operstate.lo/up", 1)
	first.want(t, "system.file_nr_used/used", 2048)
	first.want(t, "disk_space_utilization_//used", float64(1<<19)/float64(1<<20-1000)*100)
	first.want(t, "disk_inodes_utilization_/var/lib data/used", 75)
	if _, ok := first["system.cpu/user"]; ok {
		t.Fatal("cpu percentages need two samples")
	}
	if _, ok := first["disk_space_/proc/used"]; ok {
		t.Fatal("pseudo filesystems must be skipped")
	}

	rewrite(t, filepath.Join(proc, "stat"), "cpu  1000 10 500 8000 100 20 30 5 0 0", "cpu  1060 10 520 8100 100 20 20 5 0 0")
	rewrite(t, filepath.Join(proc, "stat"), "ctxt 500000", "ctxt 500500")
	rewrite(t, filepath.Join(proc, "net", "dev"), "eth0: 1000000   10000    1    2", "eth0: 1125000   10100    1    4")
	rewrite(t, filepath.Join(proc, "diskstats"), "sda 1000 0 20000 500 2000 0 40000 1000 0 1200 1500", "sda 1010 0 20200 510 2010 0 40400 1010 0 1700 1700")
	rewrite(t, filepath.Join(proc, "net", "snmp"), "8000 7000 10 0 5 0", "8100 7100 12 0 5 0")
	rewrite(t, filepath.Join(proc, "net", "netstat"), "0 0 0 5 5 10", "0 0 0 8 8 10")
	rewrite(t, filepath.Join(proc, "net", "softnet_stat"), "00001000 00000001", "00001100 00000003")
	second := runAll(cs, ems, t0.Add(time.Second))

	// cpu deltas: user 60, system 20, idle 100, softirq -10 (clamped 0): total 180
	second.want(t, "system.cpu/user", 60.0/180*100)
	second.want(t, "system.cpu/system", 20.0/180*100)
	second.want(t, "system.ctxt/switches", 500)
	second.want(t, "net.eth0/received", 125000*8.0/1000)
	second.want(t, "net_drops.eth0/inbound", 2)
	second.want(t, "net_packets.eth0/received", 100)
	second.want(t, "disk.io_sda/reads", 100)
	second.want(t, "disk.ops_sda/writes", 10)
	second.want(t, "disk.util_sda/utilization", 50)
	second.want(t, "disk.await_sda/await", 10)
	second.want(t, "ipv4.tcperrors/RetransSegs", 2)
	second.want(t, "ip.tcp_accept_queue/overflows", 3)
	second.want(t, "system.softnet_stat/processed", 256)
	second.want(t, "system.softnet_stat/dropped", 2)
	if _, ok := second["disk.io_sda1/reads"]; ok {
		t.Fatal("partitions must be skipped")
	}
	if _, ok := second["disk.io_loop0/reads"]; ok {
		t.Fatal("loop devices must be skipped")
	}
}

func TestIncrementalSkipsResetsAndFirstSample(t *testing.T) {
	e := NewEmitter()
	ch := Chart{Context: "x", Units: "u"}
	t0 := time.Unix(100, 0)
	for i, raw := range []float64{10, 20, 5, 15} {
		e.Begin(t0.Add(time.Duration(i) * time.Second))
		e.Incremental(ch, "d", raw, 1)
		got := e.Samples()
		switch i {
		case 0, 2:
			if len(got) != 0 {
				t.Fatalf("step %d: expected no sample, got %v", i, got)
			}
		default:
			if len(got) != 1 || got[0].V != 10 {
				t.Fatalf("step %d: got %v", i, got)
			}
		}
	}
}

func TestParseMountinfoUnescapes(t *testing.T) {
	ms := parseMountinfo([]string{"25 22 8:2 / /var/lib\\040data rw - xfs /dev/sda2 rw", "bad line"})
	if len(ms) != 1 || ms[0].point != "/var/lib data" || ms[0].fstype != "xfs" {
		t.Fatalf("got %+v", ms)
	}
}

func TestOperstateChartedOnlyAfterUp(t *testing.T) {
	root := copyFixture(t, "host")
	state := filepath.Join(root, "sys", "class", "net", "eth0", "operstate")
	set := func(s string) {
		if err := os.WriteFile(state, []byte(s+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	nd := &NetDev{fs: fsys{proc: filepath.Join(root, "proc"), sys: filepath.Join(root, "sys")}}
	em := NewEmitter()
	run := func(sec int64) found { return runAll([]Collector{nd}, []*Emitter{em}, time.Unix(1_700_000_000+sec, 0)) }

	set("down")
	if _, ok := run(0)["net_operstate.eth0/up"]; ok {
		t.Fatal("an interface never seen up must not be charted")
	}
	set("up")
	run(1).want(t, "net_operstate.eth0/up", 1)
	set("down")
	run(2).want(t, "net_operstate.eth0/up", 0)
}
