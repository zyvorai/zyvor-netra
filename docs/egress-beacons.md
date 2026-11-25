# Periodic egress (`internal/beacon`)

Which pod keeps contacting the same destination at a steady interval? Command-and-control check-ins look like that. So do health checks, telemetry exporters and update pollers, which is why this is a list of destinations to identify and not a verdict.

It reads the retained flow history ([`flow-log.md`](flow-log.md)) and nothing else: no new collector, no payloads, nothing blocked or captured, no deny suggested.

```bash
netractl security beacons [--window 24h] [--namespace NS] [--node N] \
    [--min-events 10] [--min-period 30s] [--min-score 0.8] [--include-private] [--limit 100]
```

`GET /api/v1/security/beacons` (viewer role; a scoped principal sees only its namespaces). MCP: `netra_security_beacons`. Console: **Network Risk**, section *Periodic egress*.

DNS query beaconing is a separate detector ([`dns-detect.md`](dns-detect.md)); this one also sees traffic to a bare address.

## How a series is judged

A series is one pod on one node talking to one peer, port and protocol, egress only. Public peers only, unless `--include-private`.

1. Deltas less than 7 seconds apart are joined into one event, because a transfer can span several 3-second agent reports.
2. A series with fewer than `min_events` events is not judged (counted in `seriesTooFewEvents`).
3. The period is the median interval between events; `jitterSeconds` is the median absolute deviation, and `dispersion` is jitter divided by period.
4. It is rejected if the period is under `min_period`, the dispersion is over 0.25, or fewer than half of the periods between the first and last event had an event.
5. The score is `0.4 * regularity + 0.1 * symmetry + 0.2 * size + 0.3 * coverage`, each from 0 to 1: regularity is 1 minus dispersion, symmetry is 1 minus the Bowley skew of the intervals (ignored while the interquartile range is only sampling noise), size is 1 minus the byte spread per event, and coverage is events seen over events expected.

The timing and size statistics follow the approach of the open-source beacon analyzer RITA (median absolute deviation and quartile skew of intervals and sizes); the weights, gates and thresholds here are Netra's own and were chosen against synthetic series, not a labelled malware corpus.

Rows on a well-known periodic port (UDP 123, port 53) carry a `hint` and are listed last. The hint is the port, not proof of what the traffic is.

## Readiness

The history inside the window must span at least `(min_events - 1) * min_period`. With less, the report says `ready: false` and lists nothing, rather than calling a quiet history clean.

## Limits

- Timing comes from counter deltas once per agent report, so periods under 20 seconds cannot be reported, and one connection that sends continuously is one long event.
- Widely randomised intervals, a new destination address on each check-in, or a period too long for the window are not found. An empty list is not proof of absence.
- Retained history is bounded in age and rows (oldest rows go first), so a busy cluster covers less than the window; `truncated` and `historySpanSeconds` say how much.
- Window 1h up to the flow retention (at most 14 days); at most 500 rows.
- To act on a destination, use [deny preview](deny-preview.md) and a leased deny.

## Validation

`go test ./internal/beacon ./internal/api -run 'Beacon|Regular|Jitter|Random|Continuous'` covers regular and jittered check-ins, 200 seeds of random (Poisson) arrivals that must report nothing, continuous transfers, multi-report events, per-pod separation, coverage gaps, ordering, readiness, parameter bounds and namespace scoping. `web/src/lib/netrisk.test.ts` covers the console helpers.
