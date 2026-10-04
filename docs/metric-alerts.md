# Metric alerts

`internal/metricalert` evaluates threshold and anomaly-rate rules against the
per-second metrics store on netrad (see [metrics.md](metrics.md)) and sends
every transition through the existing alert dispatcher (Slack, webhook,
PagerDuty and the other sinks configured for Netra alerts).

A metric alert is **read-only with respect to the datapath**. It can raise,
clear, repeat or be silenced. It never changes mode, rules or policy and is
never wired to enforcement. Only notification state (ack, silence) can be
changed through the API.

## Rule format

Rules are YAML documents with a top-level `alerts:` list. The syntax follows
Netdata's health configuration closely enough that most Netdata alarms port
with a field rename.

```yaml
alerts:
  - alarm: cpu_usage_high          # unique name
    on: system.cpu                 # metric context
    dimensions: "*"                # globs, separated by space, comma or |
    lookup: average -10m           # <function> -<window>
    aggregate: sum                 # how matched dimensions combine
    units: "%"
    every: 1m
    warn: '$this > (($status >= $WARNING) ? 75 : 85)'
    crit: '$this > (($status == $CRITICAL) ? 85 : 95)'
    delay_down: 15m
    repeat: 6h
    class: Utilization
    info: average CPU utilization over the last 10 minutes
```

| Field | Required | Meaning |
|---|---|---|
| `alarm` | yes | Rule name. A later rule with the same name replaces an earlier one. |
| `on` | yes | Context to evaluate, for example `net.net` or `workload.red_http`. |
| `charts` | no | Chart ID globs (for example `net.eth*`). Empty or `*` matches all. |
| `dimensions` | no | Dimension globs. Empty or `*` matches all. |
| `labels` | no | Map of chart labels that must match exactly (for example `namespace: shop`). |
| `lookup` | yes | `<function> -<window>`, window 1s to 31d. Functions: `average`/`avg`/`mean`, `min`, `max`, `sum`, `last`, `median`/`p50`, `p90`, `p95`, `p99`, `anomaly-rate`. |
| `aggregate` | no | `sum`, `avg`, `min` or `max` across the matched dimensions. Default is `avg` for percent units and `sum` otherwise. |
| `per` | no | Instance granularity: `chart` (default), `dimension` or `node`. |
| `vars` | no | Constants available to expressions as `$name`. |
| `calc` | no | Expression that turns the lookup result into `$this`. |
| `warn`, `crit` | one of them | Expressions; true raises the status. `crit` wins over `warn`. |
| `every` | no | Evaluation interval, default 10s, minimum 1s. |
| `delay_up` | no | How long a worse status must hold before it is raised. |
| `delay_down` | no | How long a better status must hold before it is lowered. |
| `repeat` | no | Re-notify while raised, unacknowledged and unsilenced. |
| `units`, `class`, `info` | no | Shown in the API, console and notifications. |
| `enabled` | no | `false` removes the rule, including a built-in one of the same name. |

Durations accept Go syntax (`90s`, `15m`, `6h`), a bare number of seconds, or
days (`7d`).

### Instances

A rule produces one alert instance per node and, depending on `per`, per
chart, per chart and dimension, or per node. A series whose last sample is
older than the lookup window is skipped. An instance that stops producing
data goes `undefined`, and is forgotten after an hour unless it is raised.
At most 50,000 instances are tracked; extra instances are counted in
`stats.droppedInstances`.

## Expression language

`calc`, `warn` and `crit` use a small subset of Netdata's language, parsed by
a Pratt parser in stdlib Go:

- numbers, `nan`, `inf`
- `+ - * / %` (division or modulo by zero gives NaN)
- `> >= < <= == !=`, `&& || !`, the ternary `?:`, parentheses
- `abs(x)`, `min(a, b, ...)`, `max(a, b, ...)`

Any comparison involving NaN is false, so a rule over missing data never
raises an alert.

| Variable | Value |
|---|---|
| `$this` | The aggregated lookup result, or the `calc` result once `calc` runs. |
| `$<dimension>` | That dimension's lookup result within the instance, for example `$responses` or `$errors_5xx`. Dimension names must be valid identifiers to be referenced. |
| `$status` | Current status code: `$UNDEFINED` (-1), `$CLEAR` (1), `$WARNING` (3), `$CRITICAL` (4). |
| `$anomaly_rate` | Percent of samples in the window flagged anomalous (see [anomaly-detection.md](anomaly-detection.md)). |
| `$ncpu` | Number of CPUs on the node. |
| `$now` | Unix seconds. |
| `$<var>` | A constant from the rule's `vars`. |

Unknown variables evaluate to NaN.

### Hysteresis

Use `$status` to raise at one threshold and clear at a lower one:

```yaml
warn: '$this > (($status >= $WARNING) ? 75 : 85)'
```

The alert raises above 85 and clears only below 75. Combine this with
`delay_down` to keep a flapping metric from paging repeatedly.

## Built-in rules

The embedded pack (`internal/metricalert/defaults.yaml`) covers:

| Area | Rules |
|---|---|
| CPU and load | `cpu_usage_high`, `cpu_iowait_high`, `cpu_steal_high`, `load_average_high`, `cpu_pressure_some` |
| Memory | `ram_in_use`, `oom_kill`, `memory_pressure_full`, `swap_used_high`, `swap_io_heavy` |
| Disk | `disk_space_usage`, `disk_inode_usage`, `disk_util_high`, `disk_await_high`, `io_pressure_full` |
| Interfaces | `interface_inbound_drops`, `interface_outbound_drops`, `interface_errors`, `interface_fifo_errors`, `interface_down`, `interface_carrier_changes`, `softnet_dropped`, `softnet_squeezed` |
| TCP and UDP | `tcp_listen_overflows`, `tcp_syn_queue_drops`, `tcp_syncookies_sent`, `tcp_backlog_drops`, `tcp_retransmit_timeouts`, `tcp_memory_pressure`, `udp_receive_buffer_errors`, `udp_send_buffer_errors` |
| Conntrack and system | `conntrack_table_full`, `conntrack_insert_failed`, `file_descriptors_high`, `processes_blocked` |
| Workloads (cgroups) | `workload_cpu_throttling`, `workload_memory_near_limit`, `workload_oom_kill` |
| Workload network RED | `workload_tcp_retransmits`, `workload_http_5xx_ratio` (only once a workload has at least 20 responses in 5 minutes), `workload_srtt_high` |
| Netra datapath | `kernel_drops_high`, `policy_drops_high`, `tcp_resets_high` |
| Anomaly | `node_anomaly_rate`, `network_anomaly_rate` |

`interface_down` only covers interfaces the agent has seen up since it
started; idle bridges and unplugged ports are never charted in
`net.operstate`, so they do not alert. Read the YAML for exact thresholds. To change one, put a rule with the same
`alarm` name in the rules directory; to drop one, set `enabled: false`.

## Silences and acknowledgement

- **Ack** stops repeat notifications for one raised instance until its next
  status change.
- **Silence** suppresses notifications for every instance matching the rule,
  node and chart globs (at least one is required) until it expires, at most
  30 days ahead. Status is still tracked and shown, marked `silenced`. At
  most 1,000 silences; with a data directory they persist in
  `metricalert-silences.json`.

Transitions (up to 1,000) are kept in history whether or not they notified.

## API and CLI

| Method and path | Purpose |
|---|---|
| `GET /api/v1/metrics/alerts?all=&history=` | Raised instances (all instances with `all=true`), recent transitions, rules, silences and stats. |
| `POST /api/v1/metrics/alerts/{id}/ack` | Acknowledge a raised instance. |
| `POST /api/v1/metrics/alerts/silences` | Body: `rule`, `node`, `chart` globs, `duration` (for example `2h`) or `until`, `comment`. |
| `DELETE /api/v1/metrics/alerts/silences/{id}` | Remove a silence. |

```bash
netractl metrics alerts [--all] [--json]
netractl metrics ack ALERT_ID
netractl metrics silence --rule 'disk_*' --node 'worker-3' --for 2h --comment "disk swap"
netractl metrics unsilence SILENCE_ID
```

MCP: `netra_metrics_alerts` (read-only) and the `netra://metrics/alerts`
resource. Ack and silence are not exposed over MCP. The console's Alerts view
on the Metrics page shows the same snapshot.

Raised metric alerts also feed AI briefs and digests as `metric-alert`
findings (see [ai.md](ai.md)).

## Configuration

| Variable (netrad) | Default | Meaning |
|---|---|---|
| `NETRA_METRICALERT_ENABLED` | `true` | `false` turns the engine off. It also needs `NETRA_METRICS_ENABLED`. |
| `NETRA_METRICALERT_DEFAULTS` | `true` | `false` skips the built-in pack. |
| `NETRA_METRICALERT_DIR` | `/etc/netra/metricalert.d` | `*.yaml` / `*.yml` files loaded in name order on top of the defaults. |

An invalid rule disables the engine and logs the error rather than running
with a partial pack.

Helm:

```yaml
metricsPlatform:
  alerts:
    enabled: true
    defaults: true
    rules: |
      alerts:
        - alarm: disk_space_usage
          enabled: false
        - alarm: shop_http_5xx
          on: workload.red_http
          labels: {namespace: shop}
          lookup: sum -5m
          calc: '$responses >= 50 ? $errors_5xx * 100 / $responses : nan'
          units: "%"
          warn: $this > 1
          crit: $this > 10
```

`rules` is rendered into the `netra-metricalert` ConfigMap and mounted at
`/etc/netra/metricalert.d`.
