# Port-scan / lateral-movement detection (`internal/scandetect`)

Per-workload port-scan, fan-out, lateral-movement, and SYN-flood
detection from connection-attempt TCP flag data. GA and on by default
(`scandetect.enabled` / `NETRA_SCANDETECT_ENABLED=true`); set
`enabled: false` to disable.

This is distinct from `internal/denysim`'s
[deny blast-radius preview](deny-preview.md) — that's a review-only match
of a *proposed* deny against current counters, computed fresh per
request. This is a continuously-running behavioral detector that flags
*existing* traffic that already looks like scanning or lateral movement,
independent of any proposed rule.

```text
GET /api/v1/ebpf/scan-findings
netractl ebpf scan-findings
```

Netra never blocks a connection because of a finding here — every
finding is for operator/SIEM review only.

## Sources

`internal/scandetect.Detector.Observe` is fed by a `cmd/netrad` poller
(`internal/scandetect.Detector.Run`) that reads the agent's existing
fast-path event stream (`models.AgentReport.Events`), filtered to
`Protocol=="TCP" && Direction=="egress"` events with a destination.
`SynOnly`/`Reset` are derived directly from the TCP header's flags byte
(`models.FastPathEvent.TCPFlags`, read straight off the wire by the
eBPF TC hook — the same byte the kernel itself uses, not a Netra
approximation): `SynOnly` is SYN set and ACK clear; `Reset` is RST set.

**Sampling caveat, not a fabricated signal:** the datapath emits an
event for every *blocked* packet, but only samples roughly 1-in-64
*allowed* packets. This detector therefore sees every blocked/reset
connection attempt exhaustively, but only a sampled fraction of
attempts the current policy allows through. Thresholds
(`MaxDestPorts`/`MaxDestIPs`/`MinAttempts`) are counts against that
sampled+exhaustive mix, not against full packet capture — tune them
with that in mind rather than assuming 1 count = 1 real attempt for
allowed traffic.

## Why this is stateful

Like `internal/dnsdetect`, `internal/scandetect.Detector` is a
long-lived, mutex-protected object (a per-workload LRU with a rolling
time window that resets on a traffic gap), not a pure per-request
function. It's constructed once in `cmd/netrad/main.go`, shared between
the background poller and the API handler, and leader-gated in HA mode —
see [`docs/dns-detect.md`](dns-detect.md)'s "Why this is stateful"
section for the fuller explanation; the shape is identical here.

## Response shape

`GET /api/v1/ebpf/scan-findings` returns:

```json
{
  "findings": [
    {
      "id": "a1b2c3d4e5f6a7b8",
      "type": "port_scan",
      "severity": "warning",
      "score": 0.8,
      "signals": ["high-unique-ports", "high-syn-only-ratio"],
      "namespace": "prod", "pod": "scanner-1", "workload": "scanner", "comm": "nmap",
      "uniqueDstIps": 2, "uniqueDstPorts": 34,
      "attempts": 40, "synOnly": 36, "resets": 4,
      "firstSeen": "2026-09-17T10:00:00Z", "lastSeen": "2026-09-17T10:00:05Z",
      "exampleDsts": ["10.0.0.5:22", "10.0.0.5:80"]
    }
  ],
  "snapshot": {
    "attemptsSeen": 5000, "workloadsTracked": 120, "activeFindings": 1,
    "findingsTotal": {"port_scan": 3, "syn_flood": 1}
  }
}
```

`type` is one of `port_scan` (many ports, few IPs), `fan_out` (many IPs,
few ports), `lateral_movement` (wide on both axes), `syn_flood`
(high-volume, SYN-only-dominated). Returns `409` if
`NETRA_SCANDETECT_ENABLED` is not set.

## Configuration

```bash
export NETRA_SCANDETECT_ENABLED=true
# optional, all have defaults:
export NETRA_SCANDETECT_INTERVAL=30s
export NETRA_SCANDETECT_WINDOW=60s
export NETRA_SCANDETECT_MAX_DEST_IPS=50
export NETRA_SCANDETECT_MAX_DEST_PORTS=50
export NETRA_SCANDETECT_MIN_ATTEMPTS=20
```

| Env var | Default | Notes |
|---|---|---|
| `NETRA_SCANDETECT_ENABLED` | `false` | Gates the whole feature. |
| `NETRA_SCANDETECT_INTERVAL` | `30s` | Poll interval feeding `Observe`. |
| `NETRA_SCANDETECT_WINDOW` | `60s` | A workload's per-destination tracking resets after this long without traffic. |
| `NETRA_SCANDETECT_MAX_DEST_IPS` | `50` | Unique-destination-IP threshold for `fan_out`/`lateral_movement`. |
| `NETRA_SCANDETECT_MAX_DEST_PORTS` | `50` | Unique-destination-port threshold for `port_scan`/`lateral_movement`. |
| `NETRA_SCANDETECT_MIN_ATTEMPTS` | `20` | Minimum attempts in-window before any scoring runs. |

`SynRatio`/`ResetRatio`/`MaxWorkloads`/`MaxDestPerWorkload`/
`FindingsTTL`/`MaxFindings` keep `scandetect.DefaultConfig()`'s built-in
defaults; not yet exposed as env vars.

## Scope and attribution

Findings are keyed by `(namespace, pod)`. Attribution comes from the
fast-path event's own agent-side enrichment, same as `dnsdetect`.

## API and CLI

```text
GET /api/v1/ebpf/scan-findings
netractl ebpf scan-findings
```

MCP tool: `netra_ebpf_scan_findings` (read-only).

## Limits

- **Observe-only.** No blocking, no rule changes.
- **Sampling, not full capture** — see **Sources** above.
- **Absence of a finding is not proof a workload made no such attempts.**
- **In-memory only.** A `netrad` restart or HA failover resets all
  detector state to zero.
