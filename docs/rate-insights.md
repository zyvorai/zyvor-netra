# Netra Rate Insights — v0.12

Netra v0.12 adds time-windowed traffic-rate analysis on top of the cumulative standalone eBPF counters already reported by each node agent.

## Why this exists

Cumulative counters are excellent for exact totals but poor at answering questions such as “did this workload suddenly start making 10× more outbound connections?” v0.12 keeps a bounded in-memory history of consecutive agent reports and computes rates from positive counter deltas over a requested window.

A controller restart or HA leader transition intentionally discards the rolling sample history. Rate analysis then enters **warming** state until at least two fresh reports are available. Persisted rate baselines survive restart, but they are not compared against incomplete post-restart data.

## Metrics

Per source/workload Netra derives:

- packets/s
- bytes/s
- blocked events/s
- connection attempts/s
- DNS queries/s
- DNS failures/s
- TLS SNI handshakes/s
- cleartext HTTP/1 requests/s

Counter-reset intervals are skipped rather than interpreted as traffic spikes.

## Rate baseline

Operators may capture a known-good rate baseline for a selected window (default 5 minutes). The baseline is stored in Netra durable state and replicated through the same active/passive HA ownership model as other controller state.

Rate drift uses deterministic thresholds:

- at least 2× baseline plus an absolute noise floor: warning
- at least 5× baseline: high
- at least 10× baseline: critical
- a previously-zero metric must exceed a metric-specific floor before it is reported

These are operational heuristics, not statistical confidence intervals or machine learning.

## Exposure score

The exposure score combines three independent signals for each workload/source:

1. external dependency count;
2. post-baseline behavior inventory drift;
3. time-window rate drift.

The 0–100 score is deterministic and intended for triage. It is not a vulnerability score and must not be used as an authorization decision by itself.

## Remediation proposals

`/api/v1/insights/remediations` and the Insights UI can produce review-only proposals such as:

- investigate a high/critical rate anomaly;
- review an exact SNI deny for a newly observed TLS SNI;
- review an exact IP deny for a newly observed external destination.

Netra does **not** execute these proposals automatically. They are evidence bundles for an operator. Existing eBPF enforcement still requires an explicit leased enforce mode, and Cilium changes still use the existing preflight/apply workflow.

## API

- `GET /api/v1/insights/rates?window=5m`
- `GET|POST|DELETE /api/v1/insights/rate-baseline`
- `GET /api/v1/insights/rate-drift?window=5m`
- `GET /api/v1/insights/exposure?window=5m`
- `GET /api/v1/insights/remediations?window=5m&limit=50`

Supported rate windows are 30 seconds through 2 hours.

## CLI

```bash
netractl insights rates 5m
netractl insights rate-baseline capture 5m
netractl insights rate-drift 5m
netractl insights exposure 5m
netractl insights remediations 5m
```
