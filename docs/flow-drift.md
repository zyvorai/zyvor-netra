# Flow drift: new dependencies and volume shifts (`internal/flowdrift`)

Two read-only comparisons of the **recent** window against an earlier **baseline** window of the retained flow history ([`flow-log.md`](flow-log.md), 7 days by default). They read stores Netra already keeps: no new collector, no payloads, nothing is blocked or captured.

```bash
netractl insights dependency-drift [--recent 1h] [--baseline 144h] [--min-baseline 1h] [--namespace NS] [--node N] [--public-only] [--limit 100]
netractl insights volume-shift     [--recent 1h] [--baseline 144h] [--factor 3] [--min-bytes 10485760] [--namespace NS] [--node N]
```

`GET /api/v1/insights/dependency-drift` and `GET /api/v1/insights/volume-shift` (viewer role; a scoped principal sees only its namespaces, as for `GET /api/v1/flows/history`). MCP: `netra_insights_dependency_drift`, `netra_insights_volume_shift`. Console: **Flow Drift**.

These were prompted by what comparable products do with flow data: ntopng's new-host, unusual-destination and unexpected-volume baseline alerts, and the Hubble service map's role in seeing what a workload talks to before a policy is enforced. See [`RESEARCH-round4.md`](RESEARCH-round4.md).

## Dependency drift

An edge is a workload (or pod when no workload is known), direction, peer, port and protocol.

- **New**: seen in the recent window, never in the baseline. New public egress edges carry `attention` and are listed first, then by bytes.
- **Gone quiet**: seen at least 3 times in the baseline, absent from the recent window.
- **Persistent**: in both (counted only).
- A per-workload roll-up says which workloads gained or lost the most.

`insights dependency-drift` is a different view from `insights drift` (a captured behaviour baseline) and `insights dependencies` (current counters).

### Readiness

The baseline needs at least `min_baseline` (default 1h) of history before the recent window. The span is measured from the oldest retained record, so a controller that restarted recently, or a history cut by its row cap (oldest rows go first), is **not ready** and the report lists nothing as new, with `notReadyReason`. It never guesses.

## Volume shift

Per workload and direction, the byte rate (bytes per hour) of the recent window against the baseline average. `surge` when it is at least `factor` times the baseline (default 3, 1.5 to 1000) and the recent window moved at least `min_bytes` (default 10 MiB); `drop` when it is at most `1/factor` and the baseline predicts at least `min_bytes` for the window. A workload with no baseline traffic is not listed (that is a new dependency). Surges list first, then by the size of the change.

## Limits

- Built from retained flow deltas, not packets. Missing from history is a lead, not proof that it never happened.
- A restarted pod with a new IP appears as a new private edge and its old one as gone quiet. Use `--public-only`, or read the name column (DNS name or SNI when the agent joined one).
- The baseline is a single average. A nightly job or business-hours service can look like a shift; there is no time-of-day model.
- Windows: recent 1m to 48h, baseline 1h up to the flow retention (at most 14 days), at most 500 rows per list.
- Advisory only. To act on a suspicious destination, use deny preview (which checks self-lockout) and a leased deny.

## Validation

`go test ./internal/flowdrift ./internal/api -run 'Drift|Shift'` covers new, vanished and persistent edges, public-first ordering, the not-ready paths, one-off baseline rows, future and out-of-window rows, `public_only`, list limits, surge and drop thresholds and bad parameters. `web/src/lib/flowDrift.test.ts` covers the console helpers.
