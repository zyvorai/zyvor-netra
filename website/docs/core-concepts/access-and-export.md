---
sidebar_position: 3
---

# Access control and export

Everything on this page is **off by default and additive**: nothing about an existing install
changes until you turn a piece on, and the static API and agent keys keep working throughout.

## Who can do what

The controller accepts three kinds of credential, checked in this order:

1. `NETRA_API_KEY`: a shared key, always **admin**. This is your break-glass path.
2. `NETRA_CHATOPS_API_KEY`: admin, a separate trust domain used by the ChatOps integrations.
3. An OIDC/JWT bearer token, when `NETRA_OIDC_ISSUER` is set: verified against your identity
   provider's published keys; its claims decide the role.

Roles are `viewer` < `operator` < `admin`, each including the one below.

| Role | Can do |
|---|---|
| `viewer` | Read everything, plus read-only computations that happen to be POSTs (policy plan, previews) |
| `operator` | Change enforcement rules, baselines, capture control; read packet captures |
| `admin` | Change fleet posture (mode, scope, shield), apply and roll back policy, toggle features |

The audit trail names the person, not just the key. A route added in future that mutates state is
gated at operator by default, and a test fails the build if any mutating route resolves lower.

`/metrics` can be gated with `NETRA_METRICS_TOKEN`. Without it, `/metrics` stays open for in-cluster
scraping and carries aggregate, low-cardinality data only.

## Agent to controller: mutual TLS

By default an agent proves itself with one shared key. **Mutual TLS** adds a second factor a leaked
key cannot satisfy: the agent must also present a client certificate signed by a CA you control.

| Mode (`mtls.mode`) | Behavior |
|---|---|
| `off` (default) | never asks for a client certificate |
| `optional` | verifies a certificate when one is offered and records it; agents without one are still accepted |
| `required` | agent-only requests (report, capture stream, agent config) also need a verified certificate |

People (the browser, `netractl`, API keys) are never asked for a certificate. Roll out with
`optional` first: `GET /api/v1/agents` marks each agent whose latest report arrived over a verified
certificate (set by the controller from the handshake, never taken from the agent), then switch to
`required`. The agent re-reads its certificate when the files change, so cert-manager renewal needs
no restart.

The certificate is shared by all agents, so it proves "an agent", not which node. See
`docs/agent-mtls.md` for the Helm values, the cert-manager option and rotation.

## Metrics for Prometheus

- `/metrics` carries aggregate series only, unless you enable **per-workload counters**
  (`metrics.workloadLabels.enabled`): `netra_workload_<name>_total{namespace,workload}`, with a hard
  cardinality cap and an `other` bucket. The controller accumulates deltas, so a pod dying never
  makes a counter go backwards and `rate()` never spikes.
- **Network SLOs** with multi-window burn-rate alerting (`GET /api/v1/slo`), audited on every
  state change.
- The chart can render a **ServiceMonitor** and a **PrometheusRule** (`metrics.serviceMonitor`), and
  the rules are checked with `promtool` in CI.

## Pushing telemetry out

All push sinks are opt-in, best-effort (pull export keeps working when a collector is down) and
leader-only in HA, so two replicas never double-ship.

| Sink | Enable with | Sends |
|---|---|---|
| OTLP/HTTP | `NETRA_OTLP_ENDPOINT` | metrics, audit logs, and block/deny events as spans |
| Loki | `NETRA_LOKI_URL` | audit and block events, under a small bounded label set |
| Syslog | `NETRA_SYSLOG_ADDR` | audit events as RFC 5424 over UDP or TCP |
| Snowflake | `NETRA_SNOWFLAKE_ACCOUNT` | audit events (and optionally sysctl findings) |
| Alert channels | `NETRA_ALERT_CHANNELS` | webhook (HMAC-signed), Slack, Teams, e-mail, SMS/WhatsApp, HTTP bridge |

Credentials for these sinks (headers, secrets, passwords) are never logged and never appear in an API
response. Pull export in CEF, RFC 5424 syslog, JSONL and OTLP is available regardless
(`netractl export events --format cef`).
