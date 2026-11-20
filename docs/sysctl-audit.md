# Netra Sysctl Audit

Netra v0.27.95 adds a flat, baseline-checked inventory of network hardening
and tuning sysctls — security posture, IPv6 posture, TCP tuning/lifecycle,
conntrack timeouts, and ARP/neighbor/bridge settings. This is a separate
feature from [Kernel Network Diagnostics](kernel-network-diagnostics.md):
that document's findings stay **evidence-correlated** to observed
congestion/drops (a sysctl only becomes a finding when it explains an
observed problem); this feature instead reports **current settings against
an established security/hardening baseline**, independent of whether
anything is currently going wrong.

```text
GET /api/v1/ebpf/sysctl-audit?limit=100
netractl ebpf sysctl-audit
```

Netra does **not** write sysctls here either — every finding is for operator
review only.

## Sources

`internal/sysctlaudit.Collect` reads a bounded allow-list of
`/proc/sys/net/...` files directly:

1. **Global sysctls** — one instance per host: `tcp_syncookies`,
   `icmp_echo_ignore_broadcasts`, `icmp_ignore_bogus_error_responses`,
   `ip_forward`; 11 TCP tuning/lifecycle keys (`tcp_fin_timeout`,
   `tcp_keepalive_time/intvl/probes`, `tcp_tw_reuse`,
   `tcp_slow_start_after_idle`, `tcp_mtu_probing`, `tcp_sack`,
   `tcp_timestamps`, `tcp_window_scaling`, `tcp_congestion_control`,
   `tcp_fastopen`, `tcp_ecn`); 6 `net.netfilter.nf_conntrack_*` timeout keys;
   `net.bridge.bridge-nf-call-{ip,ip6}tables`; and
   `net.ipv4.neigh.default.gc_thresh{1,2,3}`.
2. **Per-interface sysctls** — enumerated by listing
   `/proc/sys/net/ipv4/conf/` and `/proc/sys/net/ipv6/conf/` (unioned, so an
   IPv4-only or IPv6-only interface is still covered for whichever category
   applies) rather than a netlink interface query. This naturally includes
   the `all`/`default` pseudo-entries alongside every real interface. For
   each interface: 7 security keys (`rp_filter`, `accept_redirects`,
   `secure_redirects`, `send_redirects`, `accept_source_route`,
   `log_martians`, `proxy_arp`), 5 IPv6 posture keys (`disable_ipv6`,
   `accept_ra`, `accept_ra_defrtr`, `use_tempaddr`, `autoconf`), and 3 ARP
   keys (`arp_filter`, `arp_ignore`, `arp_announce`).

A VLAN sub-interface name like `eth0.100` contains a literal dot that is
part of the interface name, not a sysctl-name separator — the collector
builds each path as `filepath.Join(root, "proc/sys/net", family, "conf",
iface, suffix)` with the interface as one opaque path segment, never by
splitting a joined dotted string. Missing files are normal across kernel
versions, container network namespaces, and interface types, and are simply
omitted — not treated as an error or a finding.

## Why this is stateless

Every value collected here is a **current setting**, not a cumulative
counter — there's nothing to convert into a rate or delta. Unlike
`internal/kerneldiag` (which needs `internal/store/kernel_network.go`'s
bounded sample history to turn boot-lifetime counters into interval
evidence), `internal/sysctlaudit.Build` is a pure function computed fresh
from the latest agent reports on every request, the same pattern used by
`internal/dropdiag` and `internal/pathdiag`. There is no `/sparkline`
companion endpoint.

## Response shape

`GET /api/v1/ebpf/sysctl-audit` returns a `SysctlAuditResponse`
(`internal/models/sysctl_audit.go`):

```json
{
  "summary": { "nodes": 3, "findings": 42, "critical": 1, "warnings": 2, "informational": 39, "outliers": 1 },
  "nodes": [
    {
      "node": "node-1",
      "snapshot": { "entries": [
        { "name": "net.ipv4.conf.eth0.rp_filter", "interface": "eth0", "category": "security", "value": "0", "source": "/proc/sys/net/ipv4/conf/eth0/rp_filter" }
      ]},
      "findings": [
        { "severity": "critical", "category": "security", "name": "net.ipv4.conf.eth0.rp_filter", "interface": "eth0", "currentValue": "0", "expectedValue": "1 (strict) or 2 (loose), never 0", "rationale": "rp_filter=0 disables source-address validation, allowing IP spoofing through this interface." }
      ]
    }
  ],
  "outliers": [
    { "name": "rp_filter", "interface": "eth0", "category": "security", "majorityValue": "1", "outlierNodes": ["node-1"] }
  ],
  "limitations": ["Node-level only: sysctls are host/namespace-wide, not attributed to a workload.", "..."]
}
```

`summary` is the cluster-wide aggregate across fresh (non-stale) agents;
`nodes[].snapshot.entries` is the full raw per-node inventory (what the
dashboard's per-category `<details>` panels render); `nodes[].findings` is
every entry classified against the baseline, including informational ones,
sorted worst-severity-first and capped at `limit` per node; `outliers`
flags every `(sysctl, interface, category)` where fresh nodes disagree —
scan this first rather than the full per-node dump.

### Query parameters

```text
GET /api/v1/ebpf/sysctl-audit?limit=100
```

`limit` (default 50, max 500) caps `findings` per node and the `outliers`
list — it does not cap `snapshot.entries`, which always carries the full
raw inventory for that node.

## Baseline rules

Only well-established, unambiguous misconfigurations get a real severity
verdict. Everything else in scope — `ip_forward`, `disable_ipv6`,
`accept_ra*`, `use_tempaddr`, `autoconf`, `tcp_congestion_control`,
`tcp_fastopen`, `tcp_ecn`, `tcp_fin_timeout`/`keepalive_*`/`tw_reuse`/
`slow_start_after_idle`/`mtu_probing`, all 6 conntrack timeouts,
`bridge-nf-call-*`, `arp_filter`/`arp_ignore`/`arp_announce`, and
`neigh.default.gc_thresh*` — is genuinely context-dependent (a k8s node
legitimately runs with `ip_forward=1`; there is no universally "correct"
congestion-control algorithm or conntrack timeout) and is always reported
with severity `info` and no expected-value verdict, by design.

| Sysctl | Expected | Severity | Rationale |
|---|---|---|---|
| `*.rp_filter` | `1` or `2`, never `0` | critical | Disables source-address validation, enabling IP spoofing. |
| `*.accept_redirects` | `0` | critical | Lets an on-path attacker rewrite routes via ICMP redirects. |
| `*.secure_redirects` | `0` | critical | Narrows but doesn't close the ICMP-redirect route-rewrite risk. |
| `*.accept_source_route` | `0` | critical | Lets a sender dictate the return path, bypassing routing/firewall assumptions. |
| `tcp_syncookies` | `1` | critical | Primary kernel defense against SYN-flood exhaustion of the listen backlog. |
| `tcp_sack` | `1` | warning | Disabling is almost always accidental legacy config; hurts loss recovery. |
| `tcp_timestamps` | `1` | warning | Disabling removes RTT/PAWS support; rarely intentional. |
| `tcp_window_scaling` | `1` | warning | Disabling caps throughput on any real bandwidth-delay-product path. |
| `*.proxy_arp` | `0` unless intentional | warning | An unexpected `1` usually means it was left on by accident. |
| `*.log_martians` | `1` | warning | Low-cost early warning of spoofing/misconfiguration. |

## Scope and attribution

Node-level only, like Kernel Network Diagnostics — sysctls are host/network-
namespace-wide settings, not attributable to a specific workload. A
container running in its own network namespace may expose only a subset of
the host's interfaces and sysctls; `outliers` naturally excludes an
interface that only exists on some nodes rather than comparing it against
nodes where it's absent.

## API and CLI

```text
GET /api/v1/ebpf/sysctl-audit?limit=100
netractl ebpf sysctl-audit
```

The dashboard exposes this under **Sysctl Audit** (cluster pulse card,
outliers card, and per-node findings + per-category drill-down panels).

## Export

Netra vX.Y.Z adds an optional Snowflake export of this data
(`NETRA_SNOWFLAKE_SYSCTL_ENABLED=true`), alongside the existing audit-log
export — see [`docs/snowflake-export.md`](snowflake-export.md) for setup,
configuration, and table schema. Because findings here have no timestamp
of their own and are recomputed fresh on every call (see **Why this is
stateless** above), the export re-sends the full current snapshot on
every tick rather than watermarking; a `NETRA_SYSCTL_AUDIT_DEDUP` view
(documented in the export doc) collapses that down to the latest
observation per `(node, category, name, interface)`.

## Limits

The baseline is a generic, established hardening/lifecycle baseline, not a
workload- or deployment-specific policy — a `critical`/`warning` finding is
worth reviewing, not an automatic misconfiguration in every environment
(e.g. a host deliberately configured as a NAT gateway may run with
`proxy_arp=1` on purpose). Netra never applies any value; every suggestion
here is for manual, reviewed change through the host's normal configuration
management.
