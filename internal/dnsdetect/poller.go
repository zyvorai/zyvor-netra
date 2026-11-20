// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package dnsdetect

import (
	"context"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// Run polls fetch() on interval and feeds every fresh, matched DNS-response
// event (across all non-stale agents) into Observe. First tick is an
// immediate catch-up, matching the poll loops elsewhere in this codebase
// (internal/siem.Forwarder.Run, internal/snowflakesink.Sink.Run).
//
// fetch is typically st.AgentStatuses bound to a fixed staleAfter — see
// cmd/netrad/main.go's startDNSDetect.
//
// Dedup against redelivery of the same event across ticks is by a
// per-node TimestampNS watermark: models.AgentStatus.Events is always the
// agent's full current ring buffer (there is no "since" accessor, unlike
// store.Audit's tail-N), so the same event would otherwise be observed
// again on every subsequent tick until it ages out of the ring.
func (d *Detector) Run(ctx context.Context, interval time.Duration, fetch func() []models.AgentStatus) {
	if d == nil || fetch == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}

	watermark := make(map[string]uint64)
	drain := func() {
		for _, a := range fetch() {
			if a.Stale {
				continue
			}
			last := watermark[a.Node]
			newest := last
			for _, ev := range a.Events {
				if ev.TimestampNS <= last {
					continue
				}
				if ev.TimestampNS > newest {
					newest = ev.TimestampNS
				}
				if !isDNSResponse(ev) {
					continue
				}
				d.Observe(Query{
					Name:      ev.DNSQuery,
					QType:     ev.DNSQType,
					RCode:     ev.DNSRcode,
					Timestamp: ev.ObservedAt,
					Namespace: ev.Namespace,
					Pod:       ev.Pod,
					Workload:  ev.WorkloadName,
					Node:      a.Node,
					CgroupID:  ev.CgroupID,
					PID:       ev.PID,
					UID:       ev.UID,
					Comm:      ev.Comm,
				})
			}
			watermark[a.Node] = newest
		}
	}

	tick := time.NewTicker(interval)
	defer tick.Stop()
	drain()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			drain()
		}
	}
}

// isDNSResponse mirrors cmd/netractl/dns.go's dnsResponseFinding filter —
// the one place this codebase already defines "a real, matched DNS
// response leg" precisely. Feeding from the response leg specifically
// (rather than any event with a non-empty DNSQuery) avoids double-counting
// the same logical query once per leg, and guarantees DNSRcode is a real
// answered/failed verdict rather than the query leg's always-zero
// placeholder.
//
// QType comes from the complete first ordinary DNS question; zero means
// unavailable. Compressed/truncated questions and encrypted DNS stay unknown.
func isDNSResponse(e models.FastPathEvent) bool {
	return e.Type == "dns-response" && e.Action == "observed" && e.Protocol == "UDP" &&
		e.Hook == "cgroup" && e.Direction == "ingress" && e.SourcePort == 53 &&
		e.DNSQuery != "" && e.DNSRcode <= 15
}
