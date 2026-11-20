# OTLP push export

Netra can push its telemetry to an OpenTelemetry collector over
**OTLP/HTTP (JSON)**. It is the push counterpart to the pull-only
`GET /api/v1/export/*?format=otlp|otlp-trace` endpoints
(`docs/siem-export.md`), and a third push sink beside syslog and Snowflake:
independently configured, off by default, best-effort, leader-only in HA.

## What is pushed

| Signal    | Source                                   | OTLP shape                                   |
|-----------|------------------------------------------|----------------------------------------------|
| `metrics` | The text `GET /metrics` serves           | Gauge, monotonic cumulative Sum, Histogram   |
| `logs`    | Audit events (`store.Audit`)             | One log record per event                     |
| `traces`  | Block/deny events from node agents       | One parentless span per event                |

Spans are **not** distributed traces: each blocked/denied event is a single
zero-parent span with a fresh random trace ID, exactly as the pull
`otlp-trace` export renders it. There is no causal linkage between events.

### Metrics come from `/metrics`, not a second list

The exporter reads the running API's own `/metrics` output in-process and
converts it: `# TYPE counter` becomes a monotonic cumulative sum (start time =
process start), `gauge` stays a gauge, and `_bucket`/`_sum`/`_count` series are
re-assembled into an OTLP histogram. Because there is one source, a metric is
pushed the moment it is scrapeable and the two can never drift.

- Untyped and summary samples are exported as gauges.
- Non-finite values (`NaN`, `±Inf`) are skipped; OTLP/JSON cannot carry them.
- The histogram overflow bucket is derived from `_count`, so per-bucket counts
  always sum to the reported count.
- The internal scrape is a normal request and is counted in
  `netra_http_requests_total` (one per push interval).

## Configuration

Set on the controller (`netrad`). Nothing starts unless
`NETRA_OTLP_ENDPOINT` is set. A bad value fails startup, like the other sinks.

| Variable               | Default | Meaning |
|------------------------|---------|---------|
| `NETRA_OTLP_ENDPOINT`  | (off)   | Collector **base** URL, e.g. `http://otel-collector:4318`. `/v1/metrics`, `/v1/logs`, `/v1/traces` are appended. A path prefix (`https://gw/otel`) is fine; a URL already ending in `/v1/<signal>`, carrying credentials, a query, or a non-http(s) scheme is rejected. |
| `NETRA_OTLP_HEADERS`   | (none)  | Extra request headers as `k1=v1,k2=v2` (the `OTEL_EXPORTER_OTLP_HEADERS` format), typically an auth token. Never logged. |
| `NETRA_OTLP_SIGNALS`   | all     | Comma-separated subset of `metrics,logs,traces`. |
| `NETRA_OTLP_INTERVAL`  | `30s`   | Push cadence. |
| `NETRA_OTLP_TIMEOUT`   | `5s`    | Per-request timeout. |

Helm:

```yaml
otlp:
  enabled: true
  endpoint: http://otel-collector.observability:4318
  signals: ""                 # empty = all three
  existingSecret: otel-auth   # Secret with key "headers": "Authorization=Bearer …"
```

`otlp.enabled=true` without `otlp.endpoint` fails `helm template`. Put tokens in
the Secret, never in values.

## Delivery semantics

- **Metrics** are cumulative snapshots resent every interval. A missed push
  costs nothing; the next one carries the totals.
- **Logs and spans are at-least-once, deduplicated by watermark.** Only
  events newer than the last *successful* POST are sent. A failed POST leaves
  the watermark untouched, so the same events go out next cycle. A long backlog
  is split into batches of 500; batches that succeeded are committed and a
  failure resumes from the first uncommitted one.
- **Block-event watermarks are per node.** Agents stamp `ObservedAt` on their
  own clocks, so one global cutoff would drop a lagging node's events once a
  faster node had advanced it. Block events with no timestamp are skipped
  (they cannot be deduplicated).
- **A batch the collector rejects as malformed is dropped, not retried.** HTTP
  400, 413 and 422 mean the batch can never succeed (the OTLP spec forbids
  retrying a 400), so it is logged with the collector's reason and the watermark
  moves on; retrying it forever would wedge the exporter behind one poison batch.
  Everything else — network errors, 5xx, 429, and 401/403/404 (a bad token or URL
  is fixable, so the data is kept) — is retried next cycle. Shared with the Loki
  sink (`internal/pushfeed`, `docs/loki-push.md`).
- **Redirects are failures.** A redirected POST would silently turn into a GET
  and lose the data, so a 3xx is logged as an error instead of followed.
- **Partial success** (HTTP 200 with `partialSuccess.errorMessage`) is logged
  as a warning and *not* retried: the collector accepted the batch and
  rejected part of it for a content reason a resend cannot fix.
- **HA:** only the current leader pushes; demotion cancels the exporter before
  the state store closes, so two replicas never double-ship.
- Failures never affect the API. Pull export keeps working while the collector
  is down.

## Limits

- **JSON only.** OTLP/HTTP JSON is accepted by the OpenTelemetry Collector's
  `otlp` receiver; a backend that takes only protobuf needs a collector in
  front. There is no OTLP/gRPC and no gzip.
- No OTel SDK is linked; the payloads are hand-built to keep the controller
  dependency-light.
- Metrics carry aggregate labels only, exactly as `/metrics` does. Per-workload
  series are a separate, opt-in feature.
- `netra_tcp_retransmissions` is emitted by `/metrics` both as a gauge and as a
  histogram under the same family name. They are exported as two separate OTLP
  metrics with the same name (one Gauge, one Histogram); a backend may warn
  about the name reuse. Fixing it means renaming an existing series, which is
  a separate decision.

## Verification status

Covered by unit tests (conversion, watermarks, retry, batching, redirect,
header redaction, HA lifecycle under `-race`), including a run of the **real**
API `/metrics` output through the converter, and end to end in CI
(`scripts/ci-sinks-live.sh`): a real controller pushes to a loopback OTLP/HTTP
receiver, all three signals arrive with the configured auth header and the
expected top-level shape (`resourceMetrics`, `resourceLogs`, `resourceSpans`;
the span carries the blocked packet's destination), and the token never appears
in the controller's log or any API response. Not yet exercised against a real
OpenTelemetry Collector or a vendor backend; do that once before relying on it:

```sh
cat > otel.yaml <<'EOF'
receivers: {otlp: {protocols: {http: {endpoint: 0.0.0.0:4318}}}}
exporters: {debug: {verbosity: detailed}}
service:
  pipelines:
    metrics: {receivers: [otlp], exporters: [debug]}
    logs:    {receivers: [otlp], exporters: [debug]}
    traces:  {receivers: [otlp], exporters: [debug]}
EOF
docker run --rm -p 4318:4318 -v "$PWD/otel.yaml:/etc/otel.yaml" \
  otel/opentelemetry-collector-contrib:latest --config=/etc/otel.yaml
NETRA_OTLP_ENDPOINT=http://127.0.0.1:4318 NETRA_OTLP_INTERVAL=5s ./netrad
```
