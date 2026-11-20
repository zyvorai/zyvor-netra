// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/tsdb"
)

// reportReplay holds the samples computed from the last agent report. The
// agent builds a report every few seconds while collectors tick every
// second; repeating the last rates between reports keeps the series flat
// instead of a 0,0,3x sawtooth. A report that stops changing stops being
// replayed after maxReplay ticks.
type reportReplay struct {
	last    *models.AgentReport
	cached  []tsdb.Sample
	replays int
}

const maxReplay = 15

// replay re-emits the cached samples when r is unchanged and reports
// whether it did (or whether r is too stale to emit at all).
func (p *reportReplay) replay(r *models.AgentReport, e *Emitter) bool {
	if r != p.last {
		return false
	}
	p.replays++
	if p.replays > maxReplay {
		return true
	}
	for _, s := range p.cached {
		s.T = e.now.Unix()
		e.out = append(e.out, s)
	}
	return true
}

func (p *reportReplay) capture(r *models.AgentReport, e *Emitter, from int) {
	p.last, p.replays = r, 0
	p.cached = append(p.cached[:0], e.out[from:]...)
}

// Datapath turns the counters the agent already read from its own eBPF maps
// for the latest report into per-second series. It never opens a map.
type Datapath struct {
	Latest func() *models.AgentReport
	rp     reportReplay
}

func (*Datapath) Info() Info { return Info{Name: "ebpf.datapath", Family: "ebpf"} }

func (d *Datapath) Collect(_ time.Time, e *Emitter) error {
	if d.Latest == nil {
		return nil
	}
	r := d.Latest()
	if r == nil || d.rp.replay(r, e) {
		return nil
	}
	defer d.rp.capture(r, e, len(e.out))
	var pk, by, bl float64
	for _, s := range r.Stats {
		pk += float64(s.Packets)
		by += float64(s.Bytes)
		bl += float64(s.Blocked)
	}
	p := Chart{Context: "ebpf.packets", Family: "datapath", Units: "packets/s", Title: "Netra datapath packets"}
	e.Incremental(p, "observed", pk, 1)
	e.Incremental(p, "blocked", bl, 1)
	e.Incremental(Chart{Context: "ebpf.bandwidth", Family: "datapath", Units: "kilobits/s", Title: "Netra datapath bandwidth"}, "observed", by, 8.0/1000)

	type ifc struct{ in, out, blocked, packets float64 }
	ifaces := map[string]*ifc{}
	for _, f := range r.InterfaceFlows {
		name := f.Interface
		if name == "" {
			continue
		}
		x := ifaces[name]
		if x == nil {
			x = &ifc{}
			ifaces[name] = x
		}
		if f.Direction == "egress" {
			x.out += float64(f.Bytes)
		} else {
			x.in += float64(f.Bytes)
		}
		x.blocked += float64(f.Blocked)
		x.packets += float64(f.Packets)
	}
	for name, x := range ifaces {
		lbl := map[string]string{"interface": name}
		bw := Chart{Context: "ebpf.iface_bandwidth", ID: "ebpf_iface_bandwidth." + name, Family: "interfaces", Units: "kilobits/s", Title: "TCX/XDP interface bandwidth", Labels: lbl}
		e.Incremental(bw, "ingress", x.in, 8.0/1000)
		e.Incremental(bw, "egress", x.out, 8.0/1000)
		pp := Chart{Context: "ebpf.iface_packets", ID: "ebpf_iface_packets." + name, Family: "interfaces", Units: "packets/s", Title: "TCX/XDP interface packets", Labels: lbl}
		e.Incremental(pp, "observed", x.packets, 1)
		e.Incremental(pp, "blocked", x.blocked, 1)
	}

	if len(r.KernelDrops) > 0 {
		byReason := map[string]float64{}
		for _, k := range r.KernelDrops {
			name := k.ReasonName
			if name == "" {
				name = "reason_" + itoa(int(k.Reason))
			}
			byReason[name] += float64(k.Count)
		}
		names := make([]string, 0, len(byReason))
		for n := range byReason {
			names = append(names, n)
		}
		sort.Strings(names)
		kd := Chart{Context: "ebpf.kernel_drops", Family: "drops", Units: "drops/s", Title: "Kernel skb drops by reason", Type: "stacked"}
		for _, n := range names {
			e.Incremental(kd, n, byReason[n], 1)
		}
	}
	if r.TCPEvents != nil {
		t := r.TCPEvents.Totals
		ch := Chart{Context: "ebpf.tcp_events", Family: "tcp", Units: "events/s", Title: "TCP tracepoint events"}
		e.Incremental(ch, "retransmits", float64(t.Retransmits), 1)
		e.Incremental(ch, "rst_sent", float64(t.RSTSent), 1)
		e.Incremental(ch, "rst_received", float64(t.RSTReceived), 1)
		e.Incremental(ch, "state_transitions", float64(t.StateTransitions), 1)
	}
	if r.Shield != nil {
		ch := Chart{Context: "ebpf.shield", Family: "shield", Units: "packets/s", Title: "XDP shield verdicts"}
		e.Incremental(ch, "allowed", float64(r.Shield.Allowed), 1)
		e.Incremental(ch, "dropped", float64(r.Shield.Dropped), 1)
		e.Incremental(ch, "audited", float64(r.Shield.Audited), 1)
	}
	var policyPk float64
	for _, pd := range r.PolicyDrops {
		policyPk += float64(pd.Packets)
	}
	if len(r.PolicyDrops) > 0 {
		e.Incremental(Chart{Context: "ebpf.policy_drops", Family: "drops", Units: "packets/s", Title: "Policy drops"}, "dropped", policyPk, 1)
	}
	if r.ConntrackEntries > 0 {
		e.Gauge(Chart{Context: "ebpf.conntrack_entries", Family: "datapath", Units: "entries", Title: "Netra conntrack entries"}, "entries", float64(r.ConntrackEntries))
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
