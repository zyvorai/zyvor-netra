# Loki push export

Netra can push its audit events and block/deny events to **Grafana Loki**. It is
a fourth push sink beside syslog, Snowflake and OTLP: independently configured,
off by default, best-effort, leader-only in HA. Because SLO burn and recovery are
written to the audit log (`docs/workload-metrics-slo.md`), they arrive in Loki
too, with no extra wiring.

## What is pushed

| Class   | Source                                   | Labels |
|---------|------------------------------------------|--------|
| `audit` | Audit events (`store.Audit`)             | `job`, `class="audit"`, `severity` |
| `block` | Block/deny events from node agents       | `job`, `class="block"`, `severity="warning"`, `node` |

plus any static labels you set. **The whole event is the log line**, as JSON, so
you query it with `| json`:

```logql
{job="netra", class="audit"} | json | action="policy.apply"
{job="netra", class="block", node="worker-1"} | json | target="203.0.113.9"
{job="netra", class="audit"} | json | action=~"slo.burn|slo.recovered"
```

### Labels are deliberately few

Loki indexes labels, and every distinct label combination is a separate stream;
putting an IP, a target or an actor in a label is the classic way to overwhelm it.
So the labels are a fixed, bounded set — `job`, `class`, `severity` (from a fixed
vocabulary), `node` (one per cluster node) and your static labels — and every
high-cardinality field stays inside the line. The label API of a real Loki shows
exactly `class cluster job node service_name severity` after pushes of many
distinct IPs and targets (`service_name` is added by Loki itself). Loki 3 also
shows a `detected_level` field on query results (derived from `severity`); it is
Loki's own metadata, not an index label Netra sets.

## Configuration

Set on the controller. Nothing starts unless `NETRA_LOKI_URL` is set; a bad value
fails startup, like the other sinks.

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETRA_LOKI_URL` | (off) | Loki base URL (`http://loki:3100`) or the full `…/loki/api/v1/push`. http(s) only; no credentials or query in the URL. |
| `NETRA_LOKI_TENANT` | (none) | `X-Scope-OrgID`, for multi-tenant Loki. |
| `NETRA_LOKI_USERNAME` / `NETRA_LOKI_PASSWORD` | (none) | HTTP basic auth (Grafana Cloud, reverse proxies). Both or neither. |
| `NETRA_LOKI_HEADERS` | (none) | Extra headers `k=v,k2=v2`, e.g. a bearer token. Never logged. |
| `NETRA_LOKI_LABELS` | (none) | Static labels `k=v,k2=v2` (at most 8). Names must be `[a-zA-Z_][a-zA-Z0-9_]*`, not start with `__`, and cannot be `job`/`class`/`severity`/`node`. |
| `NETRA_LOKI_JOB` | `netra` | The `job` label. |
| `NETRA_LOKI_CLASSES` | both | Subset of `audit,block`. |
| `NETRA_LOKI_INTERVAL` | `15s` | Push cadence. |
| `NETRA_LOKI_TIMEOUT` | `5s` | Per-request timeout. |

Helm:

```yaml
loki:
  enabled: true
  url: http://loki-gateway.observability:80
  tenantId: netra
  labels: {cluster: prod}
  existingSecret: loki-auth      # optional keys: username, password, headers
```

`loki.enabled=true` without `loki.url` fails `helm template`. Put credentials in
the Secret, never in values.

## Delivery semantics

Shared with the OTLP exporter (`internal/pushfeed`):

- **Watermarks advance only past delivered batches.** A failed push leaves them
  alone, so the same events go out next cycle and nothing is skipped. Block
  watermarks are per node, since agents stamp events on their own clocks.
- **At-least-once is safe.** A real Loki discards an entry identical to one it
  already holds (same stream, timestamp and line), so resending after a partial
  failure creates no duplicates in Loki.
- **Retried:** network errors, 5xx, 429, and 401/403/404 (a bad token or URL is
  something you can fix, and the data is kept for when you do).
- **Dropped, not retried:** 400, 413 and 422. These mean the batch can never
  succeed — e.g. an entry older than Loki's `reject_old_samples_max_age` (7 days by
  default) or a line over 256 KiB. The drop is logged with Loki's reason. On a
  real Loki a 400 for a batch that mixes valid and too-old entries still *stores*
  the valid ones, so dropping the batch loses nothing that could have been kept.
  Retrying forever would instead wedge the sink behind one poison batch.
- **Size:** at most 500 events per step; bodies are split at 1 MiB and gzipped
  above 1 KiB. A line over 64 KiB loses its free-form `details` first, then its
  message, so it is never rejected outright.
- **Redirects are failures** (a redirected POST would silently become a GET).
- **HA:** only the leader pushes; demotion stops the sink before state closes.
- Failures never affect the API. Pull export keeps working while Loki is down, and
  events made during an outage are held (the audit ring keeps the newest 200) and
  delivered when Loki returns.

## Limits

- Only the newest 200 audit events are held in memory between pushes; an outage
  long enough to overflow that loses the oldest. Block events are limited by the
  agents' retained events.
- Events older than Loki's accepted window are dropped (see above).
- Logs only: no metrics, and no OTLP-to-Loki. (Netra can already push logs to Loki
  via an OTLP collector; this is the direct path.)
- Structured metadata is not used; every field is in the JSON line.

## Verification

- `./scripts/ci-loki-unit.sh` — the client against a fake that decodes real push
  payloads (shape, labels, ordering, gzip and size splitting, retry vs drop, secret
  redaction), the shared delivery logic, and netrad's wiring under `-race`.
- `./scripts/ci-loki-live.sh` — the **real `netrad` pushing to a real Loki**
  (multi-tenant), read back through Loki's own API: audit and block events arrive,
  `| json` works, the label set is bounded, another tenant sees nothing, and events
  made while Loki was down arrive after it returns. It needs a Loki binary
  (`LOKI_BIN`); CI installs a pinned, checksum-verified release.

It was also run on a real K3s cluster: the live controller pushed its 59 existing
audit events to an in-cluster Loki in one request (no resends across many cycles),
all valid JSON in two streams (info/warning), with the tenant and static label
applied and another tenant seeing nothing.

Behaviour of the classification above was measured against Loki 3.7.8 (204 on
success and gzip; 400 for an entry too old, and for an over-long line; 422 for an
empty push; duplicates and out-of-order entries accepted). Not yet exercised
against Grafana Cloud or a Loki behind an authenticating gateway.
