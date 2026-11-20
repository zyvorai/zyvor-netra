# TLS→cleartext protocol-downgrade correlation

Netra already captures a behavior baseline of observed TLS ClientHello SNI names and cleartext HTTP `Host` headers per workload (`docs/behavior-insights.md`, `GET /api/v1/insights/baseline`). This correlation asks one further question of that same data: for a workload/host pair that had TLS handshake history at the moment the baseline was captured, does it now also show cleartext HTTP to that exact same host?

Open **L7 → Protocol downgrades**, or:

```bash
netractl insights protocol-downgrades
```

`GET /api/v1/insights/protocol-downgrades` returns `{baselineCapturedAt, findings, l7Degraded, l7DegradedNodes}`. Each finding names the workload source, the host, and a severity: `warning` when no TLS activity to that host is currently observed at all (the stronger signal — TLS presence has disappeared), `info` when TLS is still concurrently active to the same host (weaker — likely coexistence, such as a secondary client path that never used TLS to begin with). **The `info` case is never suppressed** — a lower-confidence finding is still a finding, not silence.

## What this is not

This is coexistence-tolerant correlation over two independently-sampled metadata streams, not a verdict. It never uses "downgrade attack," "MITM," or "stripped TLS" language, and the UI and every tool description say so explicitly. Concretely:

- It cannot see *why* cleartext HTTP started — a new client that never spoke TLS to begin with looks identical to an attacker stripping TLS from an existing connection.
- Matching is by exact lowercased hostname string between the TLS SNI and the HTTP `Host` header. A service reachable under two different names (a CDN alias, a second Ingress host) will not correlate across that alias boundary.
- Coverage depends entirely on `internal/l7`'s existing best-effort TLS ClientHello / HTTP method+Host parsing from single egress skbs — not a full proxy, no multi-packet TLS record reassembly, no HTTP/2 or HTTP/3.

## Evidence boundaries

- **Baseline-relative only.** Like `insights.Drift`, this has nothing to compare against without a captured baseline (`POST /api/v1/insights/baseline`), and inherits that feature's exact same limitation: no baseline, no findings, not "no downgrades observed."
- **`source == "node"` entries are excluded deliberately.** That is the `CanonicalSource` fallback when neither pod nor cgroup attribution succeeded — correlating a TLS handshake from one unattributed process against cleartext HTTP from a completely unrelated one, both merged under the same bare `"node"` source, is exactly the cross-workload false-positive this feature exists to avoid.
- **A quiet result can mean incomplete L7 visibility, not a clean bill of health.** When `netra_l7_cgroup_egress`/`ingress` fail kernel verifier load — a real, observed failure on some kernels (a fixed jump-history limit, not a proportional complexity budget; see `docs/l7-metadata.md`) — `internal/agent/agent.go` deletes them from the BPF program collection *before* reload, so they are reported entirely **absent by name** from that node's program list, never present with `attached: false`. `l7Degraded`/`l7DegradedNodes` in the response (and a blocking banner in the UI, not a bare empty state) surface exactly this: any non-stale agent missing either L7 program by name marks that node degraded. Check this before reading `findings: []` as "no downgrades."
- **Deduplicated per workload/host pair, not per packet.** A workload with many cleartext requests to the same previously-TLS host produces one finding, not one per request.
- **Severity reflects concurrency, not certainty.** `warning` (no current TLS) is the stronger of the two signals this correlation can produce, not a confirmed conclusion; `info` (TLS still active) is honestly labeled weaker, never hidden.

## Validation

`internal/l7/degraded_test.go` covers the absence-by-name detection (present vs. absent vs. `attached: false`, stale-agent exclusion, multi-node sorting). `internal/insights/downgrade_test.go` covers severity classification (TLS-stopped vs. concurrently-active), the never-suppress-info-findings property, the no-baseline and node-scoped-source exclusions, an unrelated host never being flagged, and `l7Degraded` propagation. `internal/api/protocol_downgrades_test.go` covers the endpoint wiring end to end. `L7.tsx`'s degraded-banner and no-baseline empty state are not independently unit-tested (this page fetches and owns its own state rather than taking it as props, like every other full dashboard page in this project) — verify those manually against a live controller before relying on them.
