# Capacity forecast: conntrack and ephemeral ports

Time-to-exhaustion for two kernel resources that fail quietly: the netfilter connection-tracking table and the ephemeral port range. Read-only.

```bash
netractl capacity forecast --window 1h [--node worker-1]
```

`GET /api/v1/capacity/forecast?window=1h&node=GLOB` (window 10m to 24h, default 1h). MCP: `netra_capacity_forecast`. Console: **Network Risk**.

```json
{"node": "worker-1", "resource": "ephemeral-ports", "current": 61.2, "limit": 100,
 "slopePerHour": 14.8, "recentSlopePerHour": 15.1, "rSquared": 0.94,
 "secondsToExhaustion": 9100, "exhaustsAt": "2026-11-23T16:20:00Z",
 "severity": "warning", "confidence": "medium"}
```

## Data

| Resource | Series | Source |
|---|---|---|
| `conntrack` | `netfilter.conntrack_utilization` (entries over `nf_conntrack_max`, percent) | existing collector |
| `ephemeral-ports` | `net.ephemeral_utilization` (percent) | new collector `proc.net.ephemeral_ports` |

The new collector reads `net.ipv4.ip_local_port_range` and `/proc/net/{tcp,tcp6,udp,udp6}` every 10 seconds. Exhaustion is per destination: a client can hold at most (range size) ports toward one (local address, remote address, remote port) triple, so the busiest triple, not the total number of sockets, is the number that matters. Utilization is that busiest triple's count over the range size. Listening sockets are ignored. Also emitted: `net.ephemeral_ports` (`in_use`, `max_per_destination`, `range_size`) and `net.ephemeral_truncated`. No address or port reaches a metric; the scan is bounded (2,000,000 lines per file, 262,144 distinct triples) and flags `truncated` when it hits a bound.

A metric alert, `ephemeral_ports_exhaustion`, warns above 80 percent and goes critical above 90 percent. It notifies only.

## The forecast

A linear least-squares fit over the window, plus a second fit over the most recent third of the samples. The forecast is made only when both slopes rise, the fit is not noisy (R-squared at least 0.3), there are at least 12 samples over 5 minutes, and the limit is reached within 72 hours; the earlier of the two estimates is reported. Confidence is `low`, or `medium` with at least 30 samples and R-squared at least 0.6, and is never higher. Severity is the worse of the level (85 percent warning, 95 percent critical) and the estimate (under 1 hour critical, under 6 hours warning, under 24 hours info). A resource already at its limit is critical with an estimate of zero.

When there is no forecast the entry says why (`insufficient history`, `flat or falling trend`, `the long trend rises but the most recent samples are flat or falling`, `trend is too noisy`, `not projected to be exhausted within 72h0m0s`). Nodes with no series for a resource are listed under `gaps`.

## What it cannot see

- Ports held by SNAT or masquerade in a router's or node's conntrack table. The collector counts the host's own sockets.
- A step change (a deploy, a retry storm). A linear fit lags it; treat the time as an order of magnitude.
- It never changes a sysctl. Raising `nf_conntrack_max` or widening the port range is an operator decision with a memory or collision cost (see [`sysctl-audit.md`](sysctl-audit.md)).

Needs the metrics platform (`NETRA_METRICS_ENABLED=true`) and an agent new enough to run the collector; the endpoint returns 503 without the platform.

## Vendor context

Capacity alerts are common; a forecast to exhaustion is an operations feature of monitoring tools rather than of NDR or DDoS products. See [`RESEARCH-vendors-network.md`](RESEARCH-vendors-network.md).
