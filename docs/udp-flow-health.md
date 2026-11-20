# UDP flow health beyond DNS

DNS diagnostics (`docs/network-health.md`) only cover matched plain UDP/53
query/response pairs. Every other UDP flow — health checks, gRPC-over-UDP,
custom protocols, QUIC before the observed-counter reframe below — had no
cgroup-attributed visibility at all. `udp_flow_health` fills that in with the
same packets/bytes/last-seen shape `tcp_health` already provides for TCP.

## Attach point

The new map is populated from the *existing* `cgroup_skb/egress` and
`cgroup_skb/ingress` programs (`netra_cgroup_egress`/`netra_cgroup_ingress`,
which run `handle_v4`/`handle_v6` with `hook == HOOK_CGROUP`) — not the
`tc/egress`/`tc/ingress` programs. This matters: `handle_v4`/`handle_v6`'s
`HOOK_TC` branch hardcodes `cgroup_id = 0` (TC classifiers have no cgroup
context), so a map populated from that branch could never carry real
workload attribution. The `HOOK_CGROUP` branch already computes a real
`cgroup_id` via `bpf_get_current_cgroup_id()` for the same code path that
already updates `workload_flow_stats` — this feature adds one more LRU-map
update alongside that existing call, guarded to `IPPROTO_UDP` and unblocked
packets, with zero change to `decide4`/`decide6` or any hot-path signature.

`cgroup/sendmsg4`/`cgroup/sendmsg6` (the socket-layer hooks that already
track UDP `ConnectionAttempts`) were not used for this, because they run
before the packet is queued and have no packet-length field — only a
per-syscall send attempt, not per-packet bytes.

## What's tracked, and what isn't

Per cgroup + local/remote IP:port: packet count, byte count, last-seen
timestamp. **No send-failure or error counter is tracked.** Unlike DNS
(which pairs its own query and response and can therefore call a query
"failed"), a bare UDP `sendmsg()` has no in-kernel signal visible to any
hook Netra attaches — `cgroup/sendmsg4/6` runs before the packet is even
queued, so it can't see a later ICMP port-unreachable, and the existing
per-interface `icmp_errors` map (`docs/icmp-diagnostics.md`) isn't keyed
per-flow, so it can't be correlated back to one. Rather than invent a
counter with no real signal behind it, this is left out — the same honesty
standard applied to the QUIC-observed counter and the ICMP MTU peer-claim
caveat elsewhere in this project.

## API and UI

`GET /api/v1/ebpf/health` (`internal/health.Build`) adds `udp: []` (same
shape as `tcp`/`dns`) and three summary counters: `udpFlows`, `udpPackets`,
`udpBytes`. The Health page's **UDP PULSE** tile and **UDP FLOW HEALTH**
table render them the same way the existing TCP/DNS sections do — inline,
not a separate diagnostics sub-component, since (unlike DNS's RCODE
classification) there's no extra client-side logic to justify one.

## Evidence boundaries

- Only unblocked UDP packets increment the map; a blocked send never left
  the workload, so counting it as "flow health" would be misleading.
- Both directions of one flow (egress send, ingress reply) are folded into
  a single entry keyed by local/remote, matching `tcp_health`'s convention
  — not into two direction-specific entries.
- Counters are cumulative since map creation or LRU eviction, not rates.
- The additive `udp_flow_health` LRU map holds at most 131072 entries
  (matching `tcp_health`'s size): 56-byte keys, 24-byte values. Existing map
  layouts, `decide4`/`decide6`, and Netra's enforcement verdicts are
  unchanged.

## Validation

`bpf/tests/abi_layout_test.c` guards the `udp_flow_key`/`udp_flow_value`
struct sizes against `internal/agent`'s `[56]byte`/`[24]byte` decode.
`internal/agent`'s `TestDecodeUDPFlowHealthABI` checks the byte-offset
decode with literal bytes; `TestUDPFlowHealthUnavailableWhenMapMissing` and
`TestEnrichUDPFlowHealthSkipsZeroCgroup` cover the map-absent and
zero-cgroup enrichment paths. CI compiles the full BPF object. Before
production rollout, load the object on a supported Linux kernel, generate
UDP traffic from a workload, and confirm `udp_flow_health` entries appear
with the expected cgroup attribution — compilation and host tests alone do
not establish kernel verifier acceptance for the new `cgroup_skb`-path map
update.
