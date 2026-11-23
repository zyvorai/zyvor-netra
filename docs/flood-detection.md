# Flood detection (`internal/flooddetect`)

Inbound volumetric floods: SYN, UDP, ICMP and fragment. Detection and a **suggested** deny only. Nothing here applies a rule, changes the mode or touches a map.

```bash
netractl security floods [30m]
```

`GET /api/v1/security/floods?window=30m` (window 10m to 6h, default 30m). MCP: `netra_security_floods`. Console: **Network Risk**.

This is a different question from [`scan-detect.md`](scan-detect.md), which watches a workload's **egress** for scans and SYN floods, and from [`auto-mitigate.md`](auto-mitigate.md), which acts on them. This feature watches what arrives at a node and who sends it.

## Node findings

Per node and vector, from kernel counters already in the metrics platform:

| Vector | Signal | Floor (events/s) | Minimum ratio to baseline |
|---|---|---|---|
| syn | SYN queue overflow (`ip.tcp_syn_queue` drops plus syncookies) | 1 | 3 |
| syn | passive TCP opens (`ipv4.tcpopens`) | 500 | 4 |
| udp | datagrams received (`ipv4.udppackets`) | 5000 | 4 |
| udp | datagrams to closed ports (`ipv4.udperrors` `NoPorts`) | 200 | 4 |
| icmp | messages received (`ipv4.icmp`) | 500 | 4 |
| fragment | fragments needing reassembly (`ipv4.fragments`, new) | 200 | 4 |

The newest three buckets (their median, so one spiky bucket cannot fire) are compared with the median and median absolute deviation of everything before them. A finding needs the current level above the floor, a robust z-score of at least 6, and at least the minimum ratio over the baseline. Severity is the level over `max(baseline, floor)`: 10 times or more critical, 4 times high, otherwise warning. At least 20 clean baseline points are needed; NaN, infinite and negative points count as missing.

This is the behavioural, per-vector approach commercial DDoS appliances use, with absolute floors so a quiet node does not alarm on a small relative change. A flood already running for the whole window becomes the baseline and is not flagged: widen the window or compare with an older one.

The `ipv4.fragments` chart (`reasm_reqds`, `reasm_fails` from `/proc/net/snmp`) is new in this release. Needs the metrics platform.

## Source findings and the suggested deny

The XDP shield already reports per-source counters (SYN attempts, shield-denied packets). A tracker (`flooddetect.Tracker`, fed by a poller in `netrad` every 15 seconds) turns consecutive snapshots into per-second rates per source. A source is reported above 200/s (SYN attempts), 500/s (ICMP denied), or 2000/s (UDP and other denied). Counter resets, new sources and out-of-range intervals produce no rate. A restart discards the history, so rates are `sourcesWarming` until two observations arrive. Bounds: 5000 sources per snapshot, 2000 nodes, 100 findings. Set `NETRA_FLOODDETECT_ENABLED=false` to turn the tracker off and `NETRA_FLOODDETECT_INTERVAL` to change the poll. It needs the shield loaded for source data.

A public unicast source gets a suggestion: an `ingress` `ip` deny and the exact body for `POST /api/v1/ebpf/deny/preview`, plus the steps. Private, loopback, link-local, multicast, unspecified and malformed addresses get none and a reason: they are workloads or nodes to investigate. Each suggestion carries the self-lockout check from [`deny-preview.md`](deny-preview.md); if a deny of that address would reach a protected path (kube-apiserver, DNS, the controller, `NETRA_PROTECTED_DESTINATIONS`) the suggestion is withheld.

Applying a suggestion is the existing path and nothing new: preview, then `POST /api/v1/ebpf/deny`, then `PUT /api/v1/ebpf/mode` enforce with a lease, which fails open to observe when it expires.

## Caveats

- Source addresses of a volumetric attack are often spoofed: denying one can block an innocent address. For a large source set, rate limits or an upstream scrubbing service are the right tool.
- Rates come from counters and sampling at the node, not from a packet capture.
- The thresholds are heuristics, not statistical confidence intervals. Tune by watching the findings on your own baseline first (FortiDDoS-style detect-only operation is exactly what this is).

## Deferred

A declarative file of leased deny rules with plan, diff and apply (the F5 AS3 pattern) was researched and not built this round. Sketch: `netractl deny plan FILE` computes the diff against `GET /api/v1/ebpf/rules`, runs the lockout check on every entry and issues a preflight token bound to the file's hash (the `IssuePreflight` flow the policy and default-deny plans use); `deny apply FILE` consumes the token, requires `X-Netra-Confirm-Risk` at the plan's risk, writes through the existing per-type rule stores and never changes the mode. The apply half writes deny maps and should be developed with live Linux tests.
