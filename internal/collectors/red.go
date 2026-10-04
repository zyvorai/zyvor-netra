// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package collectors

import (
	"sort"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// WorkloadRED turns the workload-attributed counters in the agent's latest
// report into per-second network RED series (rate, errors, duration) per
// workload, so anomaly detection and metric alerts cover workloads without
// extra configuration. Same sources and caveats as GET /api/v1/insights/red:
// rate is datapath packets, errors are blocked packets, TCP retransmissions
// and RTOs, cleartext HTTP/1 5xx and DNS failures, and duration is TCP SRTT.
type WorkloadRED struct {
	Latest func() *models.AgentReport
	Max    int // workloads kept, busiest by bytes; default 200
	rp     reportReplay
}

func (*WorkloadRED) Info() Info { return Info{Name: "workload.red", Family: "workload"} }

type redAcc struct {
	ns, name, kind               string
	packets, bytes, blocked      float64
	retrans, rtos, http, http5xx float64
	dnsQueries, dnsFailures      float64
	srttWeighted, rttSamples     float64
}

func (w *WorkloadRED) Collect(_ time.Time, e *Emitter) error {
	if w.Latest == nil {
		return nil
	}
	r := w.Latest()
	if r == nil || w.rp.replay(r, e) {
		return nil
	}
	defer w.rp.capture(r, e, len(e.out))

	by := map[string]*redAcc{}
	// Unattributed host traffic has no workload and is covered by ebpf.*.
	get := func(ns, kind, name, pod string) *redAcc {
		if name == "" {
			name = pod
		}
		if name == "" {
			return nil
		}
		k := ns + "/" + name
		a := by[k]
		if a == nil {
			a = &redAcc{ns: ns, name: name, kind: kind}
			by[k] = a
		}
		return a
	}
	for _, s := range r.Stats {
		if a := get(s.Namespace, s.WorkloadKind, s.WorkloadName, s.Pod); a != nil {
			a.packets += float64(s.Packets)
			a.bytes += float64(s.Bytes)
			a.blocked += float64(s.Blocked)
		}
	}
	for _, t := range r.TCPHealth {
		if a := get(t.Namespace, t.WorkloadKind, t.WorkloadName, t.Pod); a != nil {
			a.retrans += float64(t.Retransmissions)
			a.rtos += float64(t.RTOs)
			if t.SRTTUS > 0 && t.RTTSamples > 0 {
				a.srttWeighted += float64(t.SRTTUS) * float64(t.RTTSamples)
				a.rttSamples += float64(t.RTTSamples)
			}
		}
	}
	for _, h := range r.HTTPStatus {
		if a := get(h.Namespace, h.WorkloadKind, h.WorkloadName, h.Pod); a != nil {
			a.http += float64(h.Count)
			if h.Status >= 500 && h.Status <= 599 {
				a.http5xx += float64(h.Count)
			}
		}
	}
	for _, d := range r.DNSHealth {
		if a := get(d.Namespace, d.WorkloadKind, d.WorkloadName, d.Pod); a != nil {
			a.dnsQueries += float64(d.Queries)
			a.dnsFailures += float64(d.Failures)
		}
	}

	list := make([]*redAcc, 0, len(by))
	for _, a := range by {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].bytes != list[j].bytes {
			return list[i].bytes > list[j].bytes
		}
		return list[i].ns+list[i].name < list[j].ns+list[j].name
	})
	max := w.Max
	if max <= 0 {
		max = 200
	}
	if len(list) > max {
		list = list[:max]
	}
	for _, a := range list {
		id := "red_" + sanitizeID(a.ns+"_"+a.name)
		lbl := map[string]string{"namespace": a.ns, "workload": a.name}
		if a.kind != "" {
			lbl["workload_kind"] = a.kind
		}
		ch := func(metric, family, units, title, typ string) Chart {
			return Chart{Context: "workload.red_" + metric, ID: id + "." + metric, Family: family, Units: units, Title: title, Type: typ, Labels: lbl}
		}
		rate := ch("rate", "rate", "packets/s", "Workload network packet rate", "line")
		e.Incremental(rate, "packets", a.packets, 1)
		e.Incremental(ch("bandwidth", "rate", "kilobits/s", "Workload network bandwidth", "area"), "bandwidth", a.bytes, 8.0/1000)
		errs := ch("errors", "errors", "events/s", "Workload network errors", "stacked")
		e.Incremental(errs, "blocked", a.blocked, 1)
		e.Incremental(errs, "retransmits", a.retrans, 1)
		e.Incremental(errs, "rtos", a.rtos, 1)
		if a.http > 0 {
			hr := ch("http", "rate", "requests/s", "Workload cleartext HTTP/1 responses", "line")
			e.Incremental(hr, "responses", a.http, 1)
			e.Incremental(hr, "errors_5xx", a.http5xx, 1)
		}
		if a.dnsQueries > 0 {
			dn := ch("dns", "errors", "queries/s", "Workload DNS queries", "line")
			e.Incremental(dn, "queries", a.dnsQueries, 1)
			e.Incremental(dn, "failures", a.dnsFailures, 1)
		}
		if a.rttSamples > 0 {
			e.Gauge(ch("duration", "duration", "ms", "Workload TCP smoothed RTT", "line"), "srtt", a.srttWeighted/a.rttSamples/1000)
		}
	}
	return nil
}
