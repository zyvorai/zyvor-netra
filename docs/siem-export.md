# SIEM export and operator report

Netra already retains an in-process audit log, health anomalies, and
cross-signal incident clusters. This surface **pulls** those observations
into encodings a SIEM, collector, or on-call ticket already understands.

It does **not** ship a new datapath, collect payloads, apply policy, or
extend an enforce lease. Push delivery of health anomalies remains the
existing HMAC-signed webhook path (`docs/alerting.md`).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/export/audit` | Last *N* `store.Audit` events |
| `GET` | `/api/v1/export/events` | Current health anomalies and/or incident clusters (optional audit) |
| `GET` | `/api/v1/export/flows` | Current destination-flow counters from fresh agents |
| `GET` | `/api/v1/export/blocks` | Current blocked/dropped events from fresh agents, including `otlp-trace` |
| `GET` | `/api/v1/export/status` | Configured encodings + whether syslog push is on |
| `GET` | `/api/v1/report` | Point-in-time operator briefing |
| `GET` | `/api/v1/playbooks` | Review-only next-step playbook from that briefing |
| `GET` | `/api/v1/audit/summary` | Actor/action/hour rollup of the audit log |
| `GET` | `/api/v1/ebpf/coverage` | Per-node hook/program coverage matrix |
| `POST` | `/api/v1/intel/preview` | Parse a threat-intel list; applies nothing |

All of these sit behind the same bearer token as the rest of `/api/v1/*`. Preview never writes deny maps.

### Query parameters

`/api/v1/export/audit` and `/api/v1/export/events`:

- `format` — `json` (default), `jsonl` (also `ndjson`), `cef`, `syslog` (also `rfc5424`), `otlp` (also `otel`)
- `limit` — 1–500, default 100 (audit cap)
- `include` — events only: comma list of `anomaly`, `incident`, `audit`. Default `anomaly,incident`

`/api/v1/report`:

- `format` — `markdown` (default) or `json`

Unknown formats return `400`.

## Encodings

| Format | Content-Type | Shape |
|---|---|---|
| `json` | `application/json` | `{"format","count","items":[Record,…]}` |
| `jsonl` | `application/x-ndjson` | one `Record` object per line |
| `cef` | `text/plain` | ArcSight CEF 0, vendor `Zyvor`, product `Netra` |
| `syslog` | `text/plain` | RFC5424, facility 13 (log audit), SD-ID `netra@zyvor` |
| `otlp` | `application/json` | OTLP/HTTP **Logs** JSON (`resourceLogs`). No traces, no SDK |
| `otlp-trace` | `application/json` | OTLP/HTTP **Traces** JSON (`resourceSpans`) — one zero-parent, zero-child span per record, `/api/v1/export/blocks`' primary use case |

`Record` fields: `at`, `class` (`audit`/`anomaly`/`incident`/`flow`/`block`), `severity`,
`actor`, `action`, `target`, `subject`, `message`, `sourceKey`, `kind`,
`node`, `value`, `details`. Audit `details` are the same map the store
already persists — mutators in this repo do not put payloads there.

CEF severity is 1/5/8 for info/warning/critical. Syslog PRI uses
facility 13 plus RFC5424 severity 6/4/2. OTLP `severityNumber` uses 9/13/21.
`otlp-trace` span status is `ERROR` for warning/high/critical severity,
`UNSET` otherwise — every `/api/v1/export/blocks` record is `warning`.

**OTEL spans for block/deny, shipped.** `docs/exporter-tetragon-borrow-backlog.md`
tracked this as a deferred item: the logs exporter above shipped first,
with traces explicitly deferred to "a later, separate program." That
program is `format=otlp-trace` on `/api/v1/export/blocks` — each already-
captured blocked/dropped `FastPathEvent` becomes one span with a fresh
random trace/span ID (there is no real causal chain between records, so
this is a display convenience for a trace-based backend's timeline, not
distributed tracing). No OTEL SDK in `netrad`; the JSON is built by hand,
same as the logs exporter. `format=otlp-trace` also works on
`/api/v1/export/audit`/`events`/`flows` (shared encoder), though
`/export/blocks` is the endpoint this feature was built for.

## CLI

```bash
netractl export audit --format cef --limit 200
netractl export events --format syslog --include anomaly,incident,audit
netractl export flows --format jsonl --limit 500
netractl export blocks --format otlp-trace --limit 200
netractl report
netractl report --format json
netractl playbooks
netractl audit summary
netractl intel preview ./feed.csv

# optional push (controller env, off by default, leader-only in HA)
# NETRA_SYSLOG_ADDR=127.0.0.1:514 NETRA_SYSLOG_NETWORK=udp NETRA_SYSLOG_FORMAT=syslog
```

`netractl` already pretty-prints JSON and prints non-JSON bodies raw, so
CEF/syslog/JSONL land on stdout as the encoder produced them.

## MCP

Read tools (always available, no mutation gate):

- `netra_export_audit`
- `netra_export_events`
- `netra_export_blocks`
- `netra_report`

(See `docs/mcp-integration.md`'s full reference table for the rest of the export-family tools added in later waves — `netra_export_flows`, `netra_export_status`, `netra_playbooks`, `netra_audit_summary`.)

## Cron / collector sketch

```bash
# ship CEF to a file filebeat / fluent-bit already tails
netractl export audit --format cef >> /var/log/netra/audit.cef

# POST OTLP/HTTP JSON Logs to a collector
curl -sS -H "Authorization: Bearer $NETRA_API_KEY" \
  "$NETRA_URL/api/v1/export/events?format=otlp" \
  | curl -sS -X POST -H 'Content-Type: application/json' \
      --data-binary @- http://otel-collector:4318/v1/logs
```

See `examples/siem-export.sh`.

## Snowflake export

Optional best-effort push sink, off by default, leader-only in HA — same
shape as the syslog forwarder above, but writes audit events straight
into a Snowflake table via `internal/snowflakesink` instead of dialing a
syslog collector. Optionally also exports sysctl-audit findings into a
second table (`NETRA_SNOWFLAKE_SYSCTL_ENABLED`), re-sending the full
current snapshot every tick rather than watermarking, since those
findings have no timestamp of their own. Flows, blocks, anomalies, and
incidents still have no continuous/watermarked source inside `netrad`
today (only the point-in-time pull endpoints above), so they aren't part
of either export.

See [`docs/snowflake-export.md`](snowflake-export.md) for full
Snowflake-side setup (warehouse/role/user/key-pair), example queries,
and semantics/limitations — this section stays a short summary.

Enable by setting `NETRA_SNOWFLAKE_ACCOUNT` (presence gates the
feature, same as `NETRA_SYSLOG_ADDR`):

| Var | Default | Notes |
|---|---|---|
| `NETRA_SNOWFLAKE_ACCOUNT` | (empty = off) | |
| `NETRA_SNOWFLAKE_USER` | — | required |
| `NETRA_SNOWFLAKE_PRIVATE_KEY_PATH` | — | required; unencrypted PKCS#8 or PKCS#1 PEM. Key-pair (JWT) auth only — there is no password field |
| `NETRA_SNOWFLAKE_WAREHOUSE` | — | required |
| `NETRA_SNOWFLAKE_DATABASE` | — | required |
| `NETRA_SNOWFLAKE_SCHEMA` | — | required |
| `NETRA_SNOWFLAKE_TABLE` | `NETRA_AUDIT` | created on startup if missing |
| `NETRA_SNOWFLAKE_INTERVAL` | `15s` | Go duration string |
| `NETRA_SNOWFLAKE_BATCH_SIZE` | `50` | rows per `INSERT` |
| `NETRA_SNOWFLAKE_EXTRA_COLUMNS` | (empty) | `NAME=SOURCE` pairs (`details:<key>` or `static:<value>`) promoted to extra columns |
| `NETRA_SNOWFLAKE_SYSCTL_ENABLED` | `false` | also export sysctl-audit findings, reusing this connection |
| `NETRA_SNOWFLAKE_SYSCTL_TABLE` | `NETRA_SYSCTL_AUDIT` | created on startup if missing |
| `NETRA_SNOWFLAKE_SYSCTL_INTERVAL` | `30s` | Go duration string |
| `NETRA_SNOWFLAKE_SYSCTL_BATCH_SIZE` | `50` | rows per `INSERT` |
| `NETRA_SNOWFLAKE_SYSCTL_TOPN` | `100000` | intentionally far above the HTTP handler's `limit=50` default, so the export never truncates |

A misconfigured account (bad credentials, unreachable warehouse, syntax
error) fails `netrad` startup — this is the one push sink that dials out
and validates connectivity eagerly, unlike the syslog forwarder, because
a wrong Snowflake config is easy to get right once and then forget about.

Target schema:

```sql
CREATE TABLE IF NOT EXISTS NETRA_AUDIT (
  at      TIMESTAMP_NTZ NOT NULL,
  actor   STRING,
  action  STRING,
  target  STRING,
  message STRING,
  details VARIANT
)
```

Optional sysctl-audit findings table (`NETRA_SNOWFLAKE_SYSCTL_ENABLED=true`):

```sql
CREATE TABLE IF NOT EXISTS NETRA_SYSCTL_AUDIT (
  at             TIMESTAMP_NTZ NOT NULL,
  node           STRING,
  severity       STRING,
  category       STRING,
  name           STRING,
  interface      STRING,
  current_value  STRING,
  expected_value STRING,
  rationale      STRING,
  informational  BOOLEAN
)
```

```bash
# optional push (controller env, off by default, leader-only in HA)
# NETRA_SNOWFLAKE_ACCOUNT=myorg-myaccount NETRA_SNOWFLAKE_USER=netra_svc
# NETRA_SNOWFLAKE_PRIVATE_KEY_PATH=/etc/netra/snowflake_key.p8
# NETRA_SNOWFLAKE_WAREHOUSE=NETRA_WH NETRA_SNOWFLAKE_DATABASE=NETRA NETRA_SNOWFLAKE_SCHEMA=PUBLIC
```

Same durability tradeoff as the syslog forwarder: a failed flush is
logged and dropped, not retried from this package — the store still has
the audit events for a pull export.

## Safety

- Observe-only. No mode change, no rule edit, no lease refresh.
- No application payloads, argv/cmdline, or Secret contents.
- Export is a point-in-time pull against the in-memory/persisted store
  cap (audit 1000 events). It is not a durable shipping buffer; if you
  need at-least-once push, keep using webhooks.

## Verification in CI

`ci-netractl-live.sh` runs `examples/siem-export.sh` in every format (json, jsonl, CEF, RFC 5424 syslog,
OTLP) against a real controller and checks each output's shape. `ci-sinks-live.sh` checks the push path:
audit events arrive as RFC 5424 over both UDP and TCP (`NETRA_SYSLOG_*`) and an audit line is never sent twice.
