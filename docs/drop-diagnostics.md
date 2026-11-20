# Netra Drop Diagnostics

Netra v0.14 adds Cilium-independent packet-drop and Linux network-stack pressure diagnostics. v0.27.76 added reason-name decoding, tc-qdisc coverage, and (for a subset of drops) process/workload attribution.

## Sources

Netra combines several sources rather than pretending one counter explains every loss event:

1. **eBPF raw `kfree_skb` tracepoint** — cumulative kernel skb drop-reason numbers, decoded to a best-effort human-readable name (`internal/dropreason`). The agent attaches this only when the host tracepoint format explicitly exposes a `skb_drop_reason` field (`kfreeDropReasonAvailable()` in `internal/agent/agent.go` probes `/sys/kernel/{tracing,debug/tracing}/events/skb/kfree_skb/format`).
2. **`/proc/net/softnet_stat`** — cumulative packets processed, packets dropped before protocol processing, and time-squeeze/budget-exhaustion events across CPUs.
3. **`/sys/class/net/<if>/statistics`** — receive/transmit drops and errors, receive missed errors, and receive no-handler counters per interface.
4. **tc-qdisc statistics, via netlink** (`internal/agent/qdisc_linux.go` + `qdisc.go`, `github.com/vishvananda/netlink`, equivalent to `tc -s qdisc show`) — per-interface, per-qdisc drop/overlimit/requeue/byte/packet counters, for every non-loopback interface on the node (not just TC/TCX-attached ones). Not every qdisc kind exposes a meaningful drop counter; a `0` can mean either "no drops" or "this qdisc kind does not report one" — e.g. `noqueue` (the default on most container veth/bridge interfaces) never reports drops, while `mq`/`fq`/`fq_codel`/`htb` do.

## Why the raw tracepoint

The formatted `skb:kfree_skb` tracepoint changed layout as kernel fields were added. Netra uses the raw tracepoint instead, where the drop reason is the third tracepoint argument on kernels that expose it. Userspace verifies the tracepoint format before attaching, so older kernels fail open to stack/interface/qdisc counters rather than producing bogus reason values.

## Response shape

`GET /api/v1/ebpf/drops` returns a `DropDiagnosticsResponse` (`internal/models/models.go`):

```json
{
  "summary": {
    "kernelDropEvents": 0,
    "softnetProcessed": 76537025,
    "softnetDropped": 0,
    "softnetTimeSqueeze": 156,
    "rxDropped": 3,
    "txDropped": 28,
    "rxErrors": 0,
    "txErrors": 0,
    "rxMissed": 1,
    "rxNoHandler": 0,
    "qdiscDrops": 0,
    "anomalies": [
      { "severity": "warning", "kind": "softnet-time-squeeze", "subject": "node-1", "message": "softnet processing hit its budget 156 times", "value": 156 }
    ]
  },
  "nodes": [
    {
      "node": "node-1",
      "kernelDrops": [
        { "reason": 7, "reasonName": "netfilter-drop", "protocol": "", "count": 42, "lastSeenNs": 1234567890 }
      ],
      "stack": {
        "softnetProcessed": 76537025, "softnetDropped": 0, "softnetTimeSqueeze": 156,
        "interfaces": [
          { "name": "eno8303", "rxDropped": 3, "txDropped": 0, "rxErrors": 0, "txErrors": 0, "rxMissed": 1, "rxNoHandler": 0 }
        ]
      },
      "qdiscStats": [
        { "interface": "eno8303", "kind": "mq", "handle": "8004:0", "drops": 0, "bytes": 109739337, "packets": 402144 },
        { "interface": "eno8303", "kind": "fq", "handle": "8005:0", "drops": 0, "bytes": 109739337, "packets": 402144 },
        { "interface": "veth6926378", "kind": "noqueue", "handle": "none", "drops": 0 }
      ]
    }
  ]
}
```

`summary` is the cluster-wide aggregate across all fresh (non-stale) agents; `nodes` breaks the same signals down per node (`kernelDrops` is sorted by `count` descending and capped at `limit`; `qdiscStats` is unsorted, one row per qdisc per interface — a node commonly reports 50-150+ rows since every veth/bridge/container interface gets at least a `noqueue` entry).

### Query parameters

```text
GET /api/v1/ebpf/drops?limit=100
```

`limit` (default 50, max 500) caps the number of `kernelDrops` rows returned **per node** (sorted by count, highest first) — it does not cap `qdiscStats`, `stack.interfaces`, or the node list itself.

## Anomaly kinds

`summary.anomalies` (and per-node data, before aggregation) can produce these `NetworkHealthAnomaly` kinds, all computed fresh from the current snapshot (fixed thresholds, not baseline-relative — see the note on `internal/alert`'s drop-spike alerting below for the rate-based complement):

| Kind | Fires when | Severity | Subject |
|---|---|---|---|
| `softnet-drop` | `stack.softnetDropped > 0` | `warning`, `critical` at ≥1000 | `<node>` |
| `softnet-time-squeeze` | `stack.softnetTimeSqueeze > 0` | `warning` | `<node>` |
| `interface-drop` | `rxDropped + txDropped + rxMissed > 0` for an interface | `warning` | `<node>/<interface>` |
| `interface-error` | `rxErrors + txErrors + rxNoHandler > 0` for an interface | `warning` | `<node>/<interface>` |
| `qdisc-drop` | a qdisc's `drops > 0` | `warning` | `<node>/<interface>/<qdisc-kind>` |

These point-in-time anomalies are also what `internal/alert`'s poller republishes as notify events (deduped per `(source, kind, subject)` with a cooldown), and what `internal/api/metrics.go` folds into the low-cardinality Prometheus gauges below. Separately, `internal/alert/dropbaseline.go` adds a **rate-based** signal — `kernel-drop-spike`/`policy-drop-spike` events when a `(node, reason)` key's delta since the last poll is both above an absolute floor (default 50) and several times (default 3×) its own recent average delta — these are not part of this endpoint's response, only the alerting stream.

When `NETRA_AUTO_CAPTURE=true`, a **critical** `softnet-drop` (≥1000) or critical drop-rate spike also starts a filtered, time-bounded packet capture and persists a PCAP plus a drop-incident context JSON — see `docs/capture.md` (Auto-capture), `docs/alerting.md`, and the walkthrough in `docs/tutorials/drop-incident-context.md`.

## Scope and attribution

Kernel drop reasons (`kfree_skb`) remain **node-level**. The tracepoint does not expose a trustworthy Kubernetes workload/cgroup identity, so Netra does not label a kernel reason as a specific Pod. Workload-specific TCP transport pressure remains available in Path Diagnostics through cgroup sockops.

Netra's own policy drops (`policy_drops`, surfaced by Drop Detective — see `docs/drop-detective.md`) are **partially attributable**: an egress TCP drop can be joined to the PID/comm/Pod already resolved for that connection's `tcp_health` row (`PolicyDropStat.PID`/`Comm`/`UID`/`Namespace`/`Pod`), when that connection was still tracked at report time. This attribution is structurally impossible for ingress drops (the SYN never reached an accepted local socket) and for UDP (no sockops tracking) — those always report `attributionState: "unattributable-ingress"` / `"unattributable-protocol"` rather than a blank, ambiguous PID. `"unmatched"` means attribution was attempted but the connection wasn't found in `tcp_health` at that moment (e.g. the deny fired before any socket state existed). This does not change kernel-drop scoping above — only Netra's own enforcement drops can ever carry this. The join itself (`internal/agent/dropattr.go`'s `attributePolicyDrops`) matches on `(family, localIP, localPort, remoteIP, remotePort)` between the drop's own tuple (src=local for egress) and a `tcp_health` row with a live, non-stale PID.

## API and CLI

```text
GET /api/v1/ebpf/drops?limit=100
netractl ebpf drops
```

The dashboard exposes the same data under **Drops** (Drop Pulse summary, per-node Kernel Drops, per-node Qdisc Drops, and per-node Node Stack cards).

## Prometheus

Low-cardinality gauges (`internal/api/metrics.go`), each an aggregate across all fresh agents, no per-node/per-interface/per-reason/per-qdisc label:

- `netra_kernel_skb_drops`
- `netra_softnet_dropped`
- `netra_softnet_time_squeeze`
- `netra_interface_rx_dropped`
- `netra_interface_tx_dropped`
- `netra_interface_rx_errors`
- `netra_interface_tx_errors`
- `netra_interface_rx_missed`
- `netra_interface_rx_nohandler`
- `netra_qdisc_dropped`

No interface name, qdisc kind, or drop reason is emitted as a Prometheus label — this is a deliberate cardinality-control choice; use the JSON API (above) for the per-node/per-reason/per-qdisc breakdown.

## Reason names

`reasonName` is a best-effort name for the raw kernel `reason` value, from a static table in `internal/dropreason` (source: `include/net/dropreason-core.h` in recent 5.15+ mainline kernel sources) seeded with the stable, low-numbered `SKB_DROP_REASON_*` values shared across recent LTS kernels. The `skb_drop_reason` enum is not a stable kernel ABI and grows across releases, so this table is not exhaustive: an unrecognized value falls back to `reason #<n>`, which should be interpreted against the running kernel's own enum/symbol definitions. Roughly, the table covers:

- **Generic/early-path**: `not-specified`, `no-socket`, `pkt-too-small`, `socket-filter`, `otherhost`, `ip-noproto`, `unhandled-proto`, `empty-skb`, `no-mem`, `no-buffer-space`, `no-write-space`
- **Checksum failures**: `tcp-csum`, `udp-csum`, `ip-csum`, `icmp-csum`, `csum-complete-check`
- **IP-layer**: `ip-inhdr`, `ip-rpfilter`, `ip-outnoroutes`, `no-route`, `ip-invalid-source`, `ip-invalid-dest`, `ip-tunnel-over-limit`, `ip-tunnel-error`
- **Fragmentation**: `duplicate-fragment`, `fragment-reassembly-timeout`, `fragment-too-large`, `invalid-fragment`, `pkt-too-big`
- **Netfilter/policy**: `netfilter-drop` (reason `7`), `xfrm-policy`
- **TCP-specific**: `tcp-flags`, `tcp-zerowindow`, `tcp-old-data`, `tcp-overwindow`, `tcp-ofomerge`, `tcp-rfc7323-paws`, `tcp-old-ack`, `tcp-too-old-ack`, `tcp-ack-unsent-data`, `tcp-offset-out-of-range`, `tcp-closed`, `tcp-fastopen`, `tcp-min-ttl`, `tcp-md5-notfound`, `tcp-md5-unexpected`, `tcp-md5-failure`, `socket-backlog`, `socket-rcvbuff`, `duplicate-segment`, `proto-mem`
- **Bridging/tap**: `unicast-in-l2-multicast`, `queue-purge`, `tap-filter`, `tap-txfilter`
- **Other**: `invalid-proto`

Netfilter/iptables and nftables `DROP` verdicts are **not** a separate counter — on kernels that populate `skb_drop_reason`, they surface through this same `kfree_skb` path as `netfilter-drop` (reason value `7`), or a more granular per-hook variant on newer kernels not yet in this table. Extending `netra_kfree_skb` to also capture the packet's 5-tuple (for attribution or a separate netfilter-specific counter) was considered and rejected: it would require `bpf_probe_read_kernel` on `sk_buff` internals whose field offsets are not stable kernel ABI, unlike the tracepoint argument this hook already relies on, and the skb can be partially torn down by the time `kfree_skb` fires for some reasons, so any captured tuple would be unreliable at exactly the call sites most interesting to inspect.

## Limits

These signals are diagnostics, not proof of root cause. Counters are cumulative. A non-zero softnet, interface, or qdisc counter does not prove that Cilium, the NIC, a switch, a firewall, the application, or the remote peer caused the loss. Attribution (see above) narrows *some* policy drops to a process/Pod; it is not available for kernel drops, ingress drops, or UDP, and a successful match is not proof that process caused the drop condition itself (e.g. a rate limit) — only that it was the source of the dropped packet.

## Live-verification notes (0.27.76)

Spot-checked against `212.8.248.187`: the qdisc-stats path returned 117 real rows for one node — real `mq`/`fq` entries on `eno8303` with populated `bytes`/`packets`, and dozens of `noqueue` entries (all-zero, as expected — that qdisc kind never reports drops) on veth/bridge/`cilium_*`/`lxc*` interfaces. The dashboard's "QDISC DROPS" card renders this table correctly, confirmed via a headless-Chrome pass. Not yet observed live: an actual nonzero `netfilter-drop` count or `qdisc-drop` anomaly, since no deny rule or congestion was deliberately induced on that cluster during this pass — both remain to be confirmed the next time a real drop condition occurs (or is deliberately tested) on a live node.

See `docs/interface-flow-attribution.md` for per-interface breakdown of Netra's own flow counters (not kernel drop reasons), scoped to TC/TCX-attached interfaces only.
