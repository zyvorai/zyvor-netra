# What changed, then what broke (`internal/changeline`)

One ordered timeline answering: *what changed on this cluster, and what got worse right after?* It joins signals Netra already records. It reads and orders; it never mutates a route, program, rule or alert, and never acks or silences anything.

| Signal | Class | Has an event time |
|---|---|---|
| Audit log (operator and agent actions) | change | yes |
| Netlink recorder (link, address, route, neighbor), with requester comm/pid when attributed | change | yes |
| BPF attachment findings (hook drift) | break | no, level-triggered |
| Drop attribution findings | break | no, level-triggered |
| Metric anomaly bursts (node anomaly rate of 20% or more, adjacent buckets merged) | break | yes |
| Metric alert transitions to warning or critical | break | yes |
| Metric alert clearing or other transitions | context | yes |

## API, CLI, MCP, console

```bash
netractl incidents changes --since 1h --lead 10m --node worker-1
curl -H "Authorization: Bearer $TOKEN" "$NETRA_URL/api/v1/incidents/changes?since=30m&lead=10m"
```

| Parameter | Meaning |
|---|---|
| `since` | Lookback, a Go duration from 1s to 24h. Default `1h` |
| `lead` | How long before a break a change counts as a suspect. Default `10m`, capped at `6h` |
| `node` | Keep one node's entries (cluster-wide audit entries are kept) |

MCP tool `netra_incidents_changes` (read-only, available without `NETRA_MCP_ALLOW_MUTATIONS`), prompt `netra_what_changed`. Console: **Investigate and respond, What Changed**.

## Response

- `entries`: ordered by time. Entries without an event time (`atKnown: false`) sort last as current state.
- `suspects`: for each timed break, up to five changes inside the lead window, same-node changes first (nearest first), then cluster-wide ones such as audit entries. Other nodes' changes are never paired. `sameNode` says which tier led.
- `gaps`: every blind spot found while collecting, so an empty suspect list is not read as clean. Examples: netlink recorder not reporting or overrun on a node, attachment inventory unavailable, stale agent, no fresh agents, metrics platform or metric alerts disabled, recorder overrun inside the window.
- `counts`, `truncated` (at most 2000 entries, oldest timed entries dropped first), `caveat`.

## Boundaries

- Ordering is not causation. A suspect is a recorded change that came first. The caveat is on every response and the console shows it.
- Drop and attachment findings come from current counters and inventory, not events, so they are listed as state and never paired as breaks with a time.
- Netlink history before an agent or controller restart is a blind spot, not a quiet period.
- Summaries are control characters stripped and clipped to 300 bytes. No payloads, argv or Secret contents are collected; the netlink actor is comm, pid and cgroup only, as recorded by the netlink recorder.
- Nothing here is wired to mode, rule or policy apply.

## Validation

`go test ./internal/changeline ./internal/api -run IncidentChanges` covers ordering, the lead window, node filtering and tiering, burst merging, overrun-to-gap, hostile strings and timestamps, truncation, and the API's input validation and gap reporting. `web/src/lib/changes.test.ts` covers the console helpers. No kernel component.
