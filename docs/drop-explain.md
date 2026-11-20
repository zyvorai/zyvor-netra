# Unified Drop Explain

`GET /api/v1/ebpf/explain` (and `GET /api/v1/drops/explain`, the same handler at a second URL) is the single "explain a drop" endpoint, replacing two previously separate paths:

- The Cilium-independent standalone eBPF stack (`internal/detective.Build` — see `docs/drop-detective.md`), which is always computed and is the **primary** source, per `docs/standalone-ebpf.md`'s positioning: it works with no Cilium installed.
- Hubble/Cilium flow data, which is appended **only when Hubble is configured** (`NETRA_HUBBLE_ENABLED` not explicitly `false`, and a relay address is reachable). When it isn't, or is temporarily unreachable, the endpoint still returns the standalone findings — Hubble enriches, it never gates, the response.

Implementation: `internal/detective/explain.go`'s `BuildUnified(agents, cfg, topN, hubbleFn)`. `hubbleFn` is `nil` when Hubble isn't configured (skipped entirely, no error); when it returns an error (Hubble configured but temporarily unreachable), that error is logged server-side at debug level and otherwise ignored — the standalone findings are still returned.

## Query parameters

```text
GET /api/v1/ebpf/explain?limit=20&agentLimit=50&namespace=default&pod=client
```

| Param | Default | Meaning |
|---|---|---|
| `limit` | 20 (max 100) | Max Hubble flows to explain (only relevant when Hubble is configured) |
| `agentLimit` | 50 | Passed through as `topN` to the standalone `detective.Build` — caps the number of `source: "netra"` findings |
| `namespace` | (none) | Filters Hubble flows by namespace (standalone findings are not namespace-filterable today — they come from whichever agents/policy drops exist) |
| `pod` | (none) | Filters Hubble flows by pod name |

## Response shape

```json
{
  "summary": {
    "text": "No Netra policy-drop findings. Kernel/softnet drops remain on Drop Diagnostics.",
    "policyDropPackets": 0, "policyDropFlows": 0, "conntrackEntries": 131073,
    "exactFindings": 0, "probableFindings": 0
  },
  "findings": [
    { "source": "netra", "confidence": "exact", "code": "port-deny", "reason": "3", "direction": "egress", "src": "10.42.0.211:44104", "dst": "10.42.0.140:8094", "packets": 42, "explanation": "egress tcp traffic matched Netra port-deny (42 packets). Attributed to curl (pid 1234) in pod client-1. 1 port deny rule(s) are staged.", "suggestion": "Permit only the required protocol/port pair, or clear the port deny." },
    { "source": "hubble", "code": "UNSUPPORTED_L3_PROTOCOL", "reason": "UNSUPPORTED_L3_PROTOCOL", "explanation": "Hubble reported a dropped flow.", "suggestion": "Inspect the Hubble drop reason, observation point, identities, and matching Cilium policies." }
  ],
  "sources": ["netra", "hubble"]
}
```

`summary` is exactly `internal/detective.Build`'s `DropDetectiveSummary` (standalone-only counters — Hubble findings don't affect it). `sources` lists which data sources actually contributed findings to *this* response — `["netra"]` when Hubble isn't configured/reachable, `["netra", "hubble"]` when both contributed.

### `findings[]` field reference

| Field | Present for | Meaning |
|---|---|---|
| `source` | always | `"netra"` or `"hubble"` |
| `confidence` | netra only | `exact` or `probable` — see `docs/drop-detective.md` |
| `node` | netra only | Reporting node |
| `namespace`/`pod` | netra: only if attributed; hubble: when the flow's source endpoint carries it | Process/workload identity |
| `code` | always | netra: `internal/detective`'s reason-code string (e.g. `port-deny`); hubble: Cilium's raw drop-reason string (e.g. `UNSUPPORTED_L3_PROTOCOL`, `INVALID_SOURCE_IP`, `POLICY_DENIED`) |
| `reason` | always | netra: the numeric reason code as a string; hubble: same raw string as `code` |
| `direction` | netra: always (`egress`/`ingress`); hubble: only if the flow carries a `verdict` | |
| `src`/`dst` | netra: `ip:port`; hubble: pod name when resolvable | |
| `packets` | netra only | Cumulative packet count for that policy-drop bucket |
| `explanation` | always | Human sentence — netra's is reason-specific and includes attribution when available; hubble's is Cilium's summary or a generic fallback |
| `suggestion` | always | Operator hint |

Only `source: "netra"` findings ever carry `pid`/`comm`/`attributionState` — those aren't part of `UnifiedFinding` at all (they're folded into `explanation`'s text, e.g. "Attributed to curl (pid 1234) in pod client-1.") since Hubble findings have no equivalent concept. See `internal/agent/dropattr.go` and `docs/drop-diagnostics.md`'s Scope and attribution section for what attribution does and doesn't cover.

## Breaking change

Before this change, `GET /api/v1/drops/explain` returned a Hubble-only, ad-hoc `{"items": [...], "count": N}` shape (each item from `hubble.Explain()` + `enrichExplanation()`: `dropReason`, `summary`, `suggestions` (array), `flow` (raw Cilium flow JSON)) and errored (502) whenever Hubble was unreachable, or was simply empty when Hubble was disabled. It now returns the unified schema above at the same URL — **this is a breaking response-shape change for any existing caller of that URL.** `GET /api/v1/ebpf/explain` is the new canonical URL for new integrations; `/api/v1/drops/explain` is kept only so existing bookmarks/MCP tool registrations keep working, with the new response shape. The two frontend callers (`web/src/pages/Flows.tsx`, `web/src/components/LiveFlowTerminal.tsx`) were updated in the same change to read `findings`/`explanation`/`source`/`code`/`suggestion` instead of the old `items`/`summary`/`dropReason`/`suggestions[0]`.

## Live-verification notes (0.27.76)

Confirmed working end-to-end via a headless-Chrome pass against `212.8.248.187`: clicking "Explain recent drops" on the Flows page returned real `source: "hubble"` findings (`UNSUPPORTED_L3_PROTOCOL`, `INVALID_SOURCE_IP`), rendered correctly by the updated frontend. A direct API check on the same cluster with no drop-matching flows in the current window returned `sources: ["netra"]` with an empty `findings` array and no error — confirming the "Hubble enriches, never gates" behavior when there's simply nothing to append that moment, not only when Hubble is unconfigured.

## CLI / MCP

```text
netractl drops
```

MCP tool `netra_drops_explain` calls the same endpoint (description updated to mention both sources and the `source` field).
