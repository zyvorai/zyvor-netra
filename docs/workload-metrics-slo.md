# Per-workload metrics, SLOs, and Prometheus Operator objects

Two opt-in features that share one engine, plus chart objects for Prometheus:

1. **Per-workload Prometheus counters** — `netra_workload_<name>_total{namespace,workload}`.
2. **Network SLOs** with multi-window burn-rate alerting, audited on every state change.
3. A **ServiceMonitor** and a **PrometheusRule** in the Helm chart.

Everything is off by default. `/metrics` still carries only aggregate series
(no pod or destination labels) until you turn the first one on.

## Why an accumulator sits in the middle

Node agents report counters that are cumulative since a BPF map entry was
created, per flow and per node. Adding those up per workload on each scrape looks
right until a pod dies, an entry is evicted or an agent restarts: the sum *drops*,
Prometheus reads the drop as a counter reset and adds the whole value back, and
`rate()` spikes. So the controller diffs each raw entry against its previous
value and accumulates the positive deltas (`internal/workloadobs`):

- **Monotonic by construction.** A pod disappearing never lowers a workload's
  total. A replacement pod's traffic counts from its first sighting.
- **Resets are handled.** A value below its predecessor means the counter
  restarted; what it now shows is counted, never a negative or huge jump.
- **History is not growth.** A node's first report — and a node returning after
  being stale or absent — only sets a baseline. Its lifetime totals are not
  booked as one tick of traffic.
- **Bounded memory.** Raw-entry state is capped (500k entries; overflow is counted
  in `netra_workload_tracker_dropped_total`) and forgotten after 10 silent ticks.

The same per-tick deltas feed the SLOs, so the two never disagree.

## Per-workload series

```
NETRA_METRICS_WORKLOAD_LABELS=on      # Helm: metrics.workloadLabels.enabled
NETRA_METRICS_WORKLOAD_MAX=100        # 1..1000 named workloads
NETRA_METRICS_WORKLOAD_IDLE=1h        # >= 1m; idle workloads give up their slot
NETRA_WORKLOAD_OBS_INTERVAL=60s       # 5s..5m; how often agent counters are folded in
```

| Series | Source |
|--------|--------|
| `netra_workload_packets_total`, `_bytes_total`, `_blocked_packets_total` | flow stats |
| `netra_workload_connection_attempts_total`, `_connections_blocked_total` | connect/sendmsg hooks |
| `netra_workload_dns_queries_total`, `_dns_failures_total` | cleartext UDP/53 |
| `netra_workload_http_responses_total`, `_http_5xx_total` | cleartext HTTP/1 status |

Labels are `namespace` and `workload` (`Kind/Name`, or `Pod/<name>` for a bare
pod). Traffic with no resolved workload (host processes, unresolved cgroups) has
no series here; on a real node roughly a third of flow entries are attributed, and
the aggregate `netra_*` metrics still cover the rest.

**Workload names are canonicalised.** Agents report a pod's *direct* controller, so
a Deployment's pods arrive as `ReplicaSet/checkout-6c4b4dfd7c` — a new name after
every rollout. Netra maps `ReplicaSet/<name>-<pod-template-hash>` to
`Deployment/<name>` and `Job/<name>-<scheduled-minutes>` to `CronJob/<name>`, so
one workload keeps one series across rollouts and an SLO can name it. A bare
ReplicaSet or Job whose name does not fit those generated patterns is left as
reported. Write SLO `workload` filters in the canonical form (`Deployment/checkout`).

**These are lower bounds, not exact totals.** A node agent reports a *top-N
snapshot*, not the whole map: flows are the top 1000 by cumulative packets,
connection sources the top 2000 by attempts, DNS the top 500, HTTP status the
top 1000. Consequences, all deliberate:

- Traffic in flows below the cutoff is invisible, so busy nodes under-report their
  tail.
- A flow that merely climbs into the top N has a long history; counting it would
  book that history as growth. So when a source's report is at its cap, a *first
  sighting only sets a baseline* (its first, usually small, report is not
  counted). Below the cap a new entry is genuinely new and counts in full.
- `netra_workload_report_truncated{source}` is 1 while a source is at its cap, so
  you can tell when to read counts as lower bounds. Sources: `flows`,
  `connections`, `dns`, `http`.

**There are no per-workload TCP series.** The agent's TCP-health list is capped by
a retransmission/RTT score — it holds the *worst* sockets, not a sample — so any
`retransmissions / segments` built from it would be inflated by construction. It is
left out rather than exported misleadingly.

### Cardinality is capped, and stable

At most `NETRA_METRICS_WORKLOAD_MAX` workloads get their own series, plus one
`namespace="__other__",workload="__other__"` bucket. Admission is
**busiest-first, then sticky**: once named, a workload keeps its series even if
another later gets busier, because series that come and go break `rate()`. A
named workload with no activity for the idle timeout is dropped and its slot
reused; if it returns it restarts from 0 (a normal counter reset). Nothing is lost
or double-counted: named totals plus `__other__` equal total growth.

Health of the feature itself: `netra_workload_series_named`,
`netra_workload_series_max`, `netra_workload_tracker_entries`,
`netra_workload_tracker_dropped_total`, `netra_workload_report_truncated{source}`.

Only rate/increase on these counters is meaningful. Because they start counting
at the controller's first sight, totals restart at controller failover.

## SLOs

```
NETRA_SLO_DEFINITIONS='[{"name":"checkout","namespace":"shop","workload":"Deployment/checkout",
                         "sli":"http_5xx","targetPct":99.9,"window":"30d"}]'
```

Helm: `slo.definitions` (a list of the same objects) and `slo.interval`.

| Field | Meaning |
|-------|---------|
| `name` | `[A-Za-z0-9._-]{1,64}`, unique |
| `namespace`, `workload` | optional filters; `workload` is `Kind/Name`. Empty matches all |
| `sli` | `http_5xx` or `dns_failure` (below) |
| `targetPct` | at least 50, below 100 (a number, or a string as `helm --set` produces) |
| `window` | 1h to 90d; Go durations or days (`30d`, `720h`). Default 30d |

Malformed definitions **stop `netrad` at startup** rather than being silently
defaulted.

### What an SLI is here — and is not

| `sli` | Good/total ratio |
|-------|------------------|
| `http_5xx` | non-5xx responses / responses seen — **cleartext HTTP/1 only** |
| `dns_failure` | queries answered without an error rcode / queries — cleartext UDP/53 |

**There is no TCP or latency SLI.** `tcp_retransmit` was removed: it would be computed
from the agent's worst-sockets-only TCP report and read systematically high.
There is no latency SLI either: Netra sees counters and per-flow averages, not
per-request durations, so it cannot say "99% of requests under 200ms". `http_5xx`
sees no HTTPS, HTTP/2 or gRPC (see `docs/l7-metadata.md`); a workload speaking
only those shows no data. `netra_slo_has_data` and `hasData` exist so an empty SLO
is not mistaken for a healthy one: with no observations, compliance reads 100%
and budget 1, and `hasData` is false.

### Burn-rate alerting

The Google SRE multi-window method: a page needs the burn rate above 14.4 in both
the long and short window of a pair (1h/5m, 6h/30m, 3d/6h); a ticket needs above 2
in 6h/30m. Observations are coalesced into 5-minute buckets, so a 30-day window
costs 8,640 entries per SLO and really covers 30 days (an unbucketed feed would
have been cut off at 4,096 entries — about 68 hours). The shortest window
therefore has 5-minute resolution.

Every change of state is written to the audit log as `slo.burn` (with severity,
window and burn rate) or `slo.recovered`, so it reaches the SIEM export, the OTLP
logs push and Snowflake with no extra wiring. Escalation is two events
(none→ticket, ticket→page); a burn that merely continues raises none. Recovery is
slow by design: a page clears only once the 6h short window is clean.

### Reading it

```
GET /api/v1/slo        # viewer role: per-SLO severity, compliance, budget, every window
```

and on `/metrics`: `netra_slo_alert_state{slo}` (0 ok, 1 ticket, 2 page),
`netra_slo_budget_remaining{slo}`, `netra_slo_compliance_ratio{slo}`,
`netra_slo_target_ratio{slo}`, `netra_slo_has_data{slo}` and
`netra_slo_burn_rate{slo,window}`.

## Prometheus Operator objects

```yaml
metrics:
  serviceMonitor: {enabled: true, labels: {release: kube-prometheus-stack}}
  prometheusRule: {enabled: true, labels: {release: kube-prometheus-stack}}
  workloadLabels: {enabled: true}
slo:
  definitions:
    - {name: checkout, namespace: shop, workload: Deployment/checkout, sli: http_5xx, targetPct: 99.9, window: 30d}
```

- **ServiceMonitor** scrapes `/metrics` over HTTPS (`insecureSkipVerify` defaults
  to true for the chart's self-signed cert; turn it off with a trusted cert).
  When `auth.metricsToken` is set it sends that token from the auth Secret
  (`metrics-token`); with `auth.existingSecret`, name the Secret in
  `metrics.serviceMonitor.bearerTokenSecret`. The pod `prometheus.io/*`
  annotations cannot carry a token, so use this instead of them once `/metrics`
  is gated (`docs/auth-oidc-rbac.md`). The chart's Service now carries the
  `app.kubernetes.io/name` labels the selector needs.
- **PrometheusRule** ships controller alerts (agents stale / none reporting, state
  persist errors, sustained auth failures, RBAC denials), SLO alerts when SLOs are
  defined (page on `netra_slo_alert_state == 2`, ticket on `== 1` for 15m, low
  budget only when there is data) and, with workload series on, warnings when the
  series cap is reached or the tracker drops entries.

Both need the operator's CRDs installed; the chart does not install them.

## Limits

- Counts are since the controller first saw an entry: totals restart on
  controller restart or HA failover (a normal counter reset).
- Only the leader observes; a non-leader replica exports none of it.
- SLO state is in memory: a restart empties the windows, and burn rates need time
  to rebuild. `hasData` tells you when it has.
- Definitions are configuration, not an API: no create/edit endpoint and no
  netractl or MCP command yet — only `GET /api/v1/slo`.
- No latency SLIs (see above); `http_5xx` is cleartext HTTP/1 only.
- `/metrics` also emits `netra_tcp_retransmissions` as both a gauge and a
  histogram under one family name (predates this feature; renaming would break
  existing series).

## Verification

`./scripts/ci-workload-obs-unit.sh` (accumulator, SLO registry, observer
lifecycle, exposition; under `-race`), `./scripts/ci-workload-obs-live.sh` (the real
`netrad` fed synthetic agent reports: growth, cap and `__other__`, a counter
reset, a vanished workload, a burn that pages and is audited, monotonicity), and
`./scripts/ci-prometheus-rules.sh` (`promtool check rules` plus `promtool test
rules` against `deploy/prometheus/netra-rules.test.yaml`). Chart wiring is covered
by the `helm` CI job.

Not yet run: against a real Prometheus Operator (the ServiceMonitor is validated by
rendering, not by a live scrape), or with real agent data on a real kernel.
