# Conntrack and Drop Detective

Netra v0.17 borrows FluxVM's established-flow and Drop Detective ideas without adopting VM-edge identity or Maglev. v0.27.76 added process/workload attribution for a subset of findings (see below).

## Conntrack

- New pinned map: `conntrack` (LRU) under `/sys/fs/bpf/netra`.
- Allowed TCP/UDP/other packets learn forward and reverse 5-tuples.
- On a later packet, a fresh TCP SYN always re-evaluates deny policy; non-SYN hits within the timeout may bypass newly added denies so established sessions fail open only for that tuple.
- Timeouts: TCP 1h, UDP 3m, other 1m (same order of magnitude as FluxVM).

Existing flow counter maps are unchanged.

## Policy drops

- Map: `policy_drops` (LRU hash, `bpf/netra_tc.c`), keyed by `struct policy_drop_key {family, protocol, direction, reason, src_port, dst_port, src_addr[16], dst_addr[16]}`, value `{packets, bytes, last_ns}`.
- Incremented whenever Netra's datapath decides `ACT_BLOCK` with a deny reason, at `record_policy_drop()`.
- `direction`: `0` = egress, `1` = ingress. `src_addr`/`dst_addr`/`src_port`/`dst_port` are the packet's actual source/destination — for an egress drop, `src` is always the local endpoint.
- `reason` is Netra's **own** 1-9 enum (`internal/detective.reasonNames`/`ReasonName()`) — a completely different value space from `KernelDropStat.Reason`'s kernel `skb_drop_reason` enum documented in `docs/drop-diagnostics.md`. Same field name (`reason`), disjoint meaning; do not conflate the two when reading raw API responses.

### Reason codes

| Code | `code` string | Meaning | Default `suggestion` |
|---|---|---|---|
| 1 | `exact-ip-deny` | Exact source/destination IP is on a manual deny list | Confirm the destination still needs containment, or remove the exact deny after the incident. |
| 2 | `cidr-deny` | Address falls inside a manually staged CIDR deny | Confirm the destination still needs containment, or remove the CIDR deny after the incident. |
| 3 | `port-deny` | L4 port is on a deny list | Permit only the required protocol/port pair, or clear the port deny. |
| 4 | `uid-deny` | Originating UID is denied | Inspect eBPF config and recent audit events for the matching UID deny rule. |
| 5 | `rate-limit` | Destination's emergency PPS ceiling was exceeded | Raise the emergency PPS ceiling or narrow the protected destination set. |
| 6 | `dns-deny` | Queried domain is on the DNS deny list | Review the DNS deny list for false positives before extending the lease. |
| 7 | `process-deny` | Originating process (by comm/exe) is denied | Inspect eBPF config and recent audit events for the matching process deny rule. |
| 8 | `sni-deny` | TLS SNI is on the deny list | Review the SNI deny list for false positives before extending the lease. |
| 9 | `netpol-deny` | A NetworkPolicy-shaped deny rule fired (distinct from a manual CIDR deny) | Review the NetworkPolicy-shaped deny rules (`netpolDenies`) for this workload, separate from any manual CIDR deny. |
| *(other/unmapped)* | `reason-<n>` | Reserved or not-yet-decoded reason value | Inspect eBPF config and recent audit events for the matching deny primitive. |

`confidence` is `exact` for any of the 9 mapped codes, `probable` for anything else (an unmapped/reserved reason value).

## Drop Detective API

`GET /api/v1/ebpf/diagnose` (`internal/detective.Build`) correlates agent-reported `policyDrops` with the current controller deny config (`EBPFFastPathConfig`, for CIDR/port-deny counts in the explanation text) into a `DropDetectiveResponse`:

```json
{
  "summary": {
    "text": "1 policy-drop finding(s); top cause port-deny (42 packet(s)).",
    "policyDropPackets": 42,
    "policyDropFlows": 1,
    "conntrackEntries": 100772,
    "exactFindings": 1,
    "probableFindings": 0
  },
  "findings": [
    {
      "node": "node-1",
      "confidence": "exact",
      "code": "port-deny",
      "stage": "netra-policy/port-deny",
      "reason": 3,
      "family": 4,
      "protocol": 6,
      "direction": 0,
      "src": "10.42.0.211:44104",
      "dst": "10.42.0.140:8094",
      "packets": 42,
      "bytes": 2688,
      "explanation": "egress tcp traffic matched Netra port-deny (42 packets). Attributed to curl (pid 1234) in pod client-1. 1 port deny rule(s) are staged.",
      "suggestion": "Permit only the required protocol/port pair, or clear the port deny.",
      "pid": 1234,
      "comm": "curl",
      "uid": 1000,
      "namespace": "default",
      "pod": "client-1",
      "attributionState": "attributed"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `confidence=exact` | Mapped to a known Netra reason code (exact IP, CIDR, port, …) |
| `confidence=probable` | Unknown/reserved reason |
| `code` | See the reason-code table above |
| `stage` | `netra-policy/<code>` (or `netra-policy/unknown` for `probable`) |
| `src`/`dst` | `ip:port` (bracketed for IPv6), from the drop's own tuple |
| `explanation` | Human-readable sentence: direction, protocol, reason name, packet count, attribution (if any), and a reason-specific detail sentence |
| `suggestion` | Operator hint, see table above |
| `pid`/`comm`/`uid`/`namespace`/`pod` | Process/workload identity, only present when `attributionState="attributed"` |
| `attributionState` | `attributed`, `unattributable-ingress`, `unattributable-protocol`, or `unmatched` — see `docs/drop-diagnostics.md`'s Scope and attribution section for what each means |

Findings are sorted by `packets` descending, then `code`, and capped at `limit` (query param, default 50, no documented max — pass a small value for interactive use).

Attribution joins the drop's local tuple against the same TCP connection tracking `tcp_health`/Path Diagnostics already uses (`internal/agent/dropattr.go`'s `attributePolicyDrops`, matching on `family + localIP + localPort + remoteIP + remotePort` against a `tcp_health` row with a live, non-stale PID) — it is only ever possible for **egress TCP** drops where that connection was still tracked when the report was built. Ingress drops and UDP are always unattributable by construction, not a bug — an ingress SYN-drop happens before any local socket is accepted, and UDP sends have no sockops-derived PID tracking at all in this codebase.

```text
netractl ebpf diagnose
```

The Drops dashboard page shows detective findings ("Drop Detective" card) beside kernel/softnet/qdisc counters, including a muted "not attributable (ingress)" / "not attributable (non-TCP)" / "process not found" badge when `attributionState` isn't `"attributed"`.

## Unified explain

`GET /api/v1/ebpf/explain` (and the repointed `GET /api/v1/drops/explain`) wraps this same Drop Detective output, optionally merged with Hubble/Cilium findings when Hubble is configured — see `docs/drop-explain.md` for the combined schema.

## Safety

- Observe-first and leased enforce are unchanged.
- Conntrack never invents allow rules for ports that were never established.
- No Maglev/Service Fabric code is included.
