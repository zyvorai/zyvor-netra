# Failed-connection investigation timeline

Compose existing observe surfaces into one evidence-backed timeline for a
failed or degraded connection. Observe-only: never changes mode, rules or
policy.

## API

`POST /api/v1/investigate/connection` (also `GET` with the same query params).

Body / query:

| Field | Meaning |
|---|---|
| `namespace`, `pod` | Workload scope |
| `peer`, `port` | Destination |
| `node` | Optional node filter |
| `window` | Lookback duration (default `15m`) |
| `since`, `until` | Absolute bounds (RFC3339) or `since` as duration |

Response:

- `events[]` — ordered evidence (`source`, `stage`, `summary`, `confidence`, `link`)
- `gaps[]` — stages with no data, ending with an explicit visibility boundary
- `confidence` — sensor availability, stale agents, retention gaps
- `limitations[]` — honest contract (no decrypt, no rule-ID-at-time-T)

## CLI / MCP

```bash
netractl investigate connection --namespace app --pod api --peer 10.0.0.8 --port 443 --window 15m
```

MCP tool: `netra_investigate_connection` (read-only; not behind
`NETRA_MCP_ALLOW_MUTATIONS`).

## Sources

DNS board, flow history, netlink events, drop detective / explain, path
diagnostics, drop-info, coverage matrix, capture history. No new BPF.

## See also

- [`investigation-ux.md`](investigation-ux.md) — live connection sample boundaries
- [`flow-log.md`](flow-log.md) — history and RED
- [`drop-explain.md`](drop-explain.md) — policy drop explain
- [`netlink-recorder.md`](netlink-recorder.md) — RTNL timeline
