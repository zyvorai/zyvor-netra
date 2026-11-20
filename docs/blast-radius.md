# Multi-hop blast radius (`internal/insights.BlastRadius`)

Given a node in the [dependency graph](mcp-integration.md) (`GET /api/v1/insights/dependencies`), walk outward breadth-first over edges Netra has actually observed, up to a configurable number of hops, and return every node reached and the edges used to reach it.

This answers "if traffic starts here, how far does it appear to go, based on what Netra has seen" — a workload compromise or a misbehaving pod's downstream reach, in terms of *observed* traffic, not evaluated policy.

## Use it

```bash
netractl insights dependencies             # find a node ID, e.g. "workload:prod:deployment:api"
netractl insights blast-radius workload:prod:deployment:api
netractl insights blast-radius workload:prod:deployment:api 5
```

`GET /api/v1/insights/blast-radius?root=<node id>&hops=<1-6>`. `root` is required and must be a node ID from the dependency graph — an unknown root is a `400`, not a silently empty result. `hops` defaults to 3 and is clamped to the [1, 6] range, matching `internal/insights.Exposure`'s own existing "beyond a handful of hops the graph degenerates toward the whole cluster" heuristic.

## Evidence boundaries

- **This is observed traffic reachability, never a policy determination.** A node with no edge shown here may still be *permitted* to reach further destinations that Netra simply hasn't observed traffic for in this window; conversely, an edge shown here reflects traffic Netra saw, not a live confirmation that the current policy still allows it. Every response and UI presentation of this data carries a fixed caveat string (`insights.BlastRadiusCaveat`) saying exactly this — never render or describe results as "permitted," "allowed," or "can reach" without that qualification.
- The traversal is a plain BFS: it reports *a* shortest path in hop count from the root to each node, not necessarily the most significant or highest-volume path. A node reached in 2 hops via a low-traffic edge is reported the same way as one reached in 2 hops via the cluster's busiest connection — check the returned edges' `packets`/`bytes` for volume, don't infer it from hop count.
- Built from the same `DependencyGraph` `netra_insights_dependencies` returns, so it inherits that graph's own limits: only non-stale agent reports, egress-observed and cross-referenced destination traffic, and a cap on total edges considered (`insights/blast-radius` requests the graph at the same 5000-edge ceiling `insights/exposure` and `insights/recommendations` already use, not the smaller UI default, since a partial graph would understate the true radius).
- `truncated: true` means the walk was cut off by the `hops` ceiling while nodes reachable in more hops still existed — it does not mean those further nodes don't matter, only that this call didn't walk far enough to include them. Re-run with a larger `hops` value (up to 6) to see further.
- A cycle in the graph (A talks to B talks back to A) does not loop forever or inflate hop counts — a node is recorded at the hop it was *first* reached and never revisited.
- Edges and nodes are as fresh as the live dependency graph at request time; this endpoint does no historical lookback and keeps no state of its own.

## Validation

`internal/insights/blastradius_test.go` covers: default and ceiling-clamped hop counts, truncation reported correctly at the hop boundary vs. a fully-explored graph reporting no truncation, an unknown root producing an error, cycles resolving without duplication or infinite loop, and parallel edges between the same two nodes deduplicating to one.

No kernel/BPF component — this is pure userland graph traversal over data the existing dependency-graph endpoint already computes, so standard `go test`/`go vet` coverage is sufficient; there is no live-kernel verification step for this feature.
