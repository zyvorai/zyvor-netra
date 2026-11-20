// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package scandetect

import (
	"context"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

// TCP flag bits, as laid out in the TCP header's single flags byte
// (RFC 793) — the same byte models.FastPathEvent.TCPFlags carries
// straight off the wire (bpf/netra_tc.c reads it directly out of the
// packet's tcphdr; see agent.go's fast-path event decode).
const (
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

// Run polls fetch() on interval and feeds every fresh TCP egress event
// (across all non-stale agents) into Observe. First tick is an immediate
// catch-up, matching internal/dnsdetect.Detector.Run's shape (the same
// per-node TimestampNS watermark problem applies here for the same
// reason: models.AgentStatus.Events is always the agent's full current
// ring buffer, not a since-cursor).
//
// Only Protocol=="TCP" events are considered — SynOnly/Reset are TCP
// flag-byte semantics and have no meaning for UDP. Allowed (non-blocked)
// packets are only ~1.5% sampled by the datapath (see bpf/netra_tc.c's
// submit_packet_event call sites), so this sees every blocked/reset
// attempt but a sampled fraction of allowed ones — port-scan/fan-out
// thresholds are tuned against that reality, not full packet capture.
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
				if !isTCPEgressAttempt(ev) {
					continue
				}
				d.Observe(Event{
					Timestamp: ev.ObservedAt,
					Namespace: ev.Namespace,
					Pod:       ev.Pod,
					Workload:  ev.WorkloadName,
					Node:      a.Node,
					Comm:      ev.Comm,
					DstIP:     ev.DestinationIP,
					DstPort:   ev.DestinationPort,
					SynOnly:   ev.TCPFlags&tcpFlagSYN != 0 && ev.TCPFlags&tcpFlagACK == 0,
					Reset:     ev.TCPFlags&tcpFlagRST != 0,
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

func isTCPEgressAttempt(e models.FastPathEvent) bool {
	return e.Protocol == "TCP" && e.Direction == "egress" && e.DestinationIP != ""
}
