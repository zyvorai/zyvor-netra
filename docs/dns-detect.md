# DNS anomaly detection (`internal/dnsdetect`)

Metadata-only, behavioral DNS anomaly detection: tunneling, DGA (domain
generation algorithm) lookups, beaconing, and NXDOMAIN/SERVFAIL storms.
Off by default (`NETRA_DNSDETECT_ENABLED=true`).

This is a different question from
[DNS response diagnostics](dns-response-diagnostics.md), which explains
*a single response code you already noticed* (why did this one lookup come
back NXDOMAIN?). This feature instead watches the **pattern of queries
over time** per `(registered domain, namespace, pod)` and flags query
*behavior* that looks like tunneling, a DGA, a beacon, or a resolution
storm — independent of whether any single query's response code looked
wrong.

```text
GET /api/v1/ebpf/dns-findings
netractl ebpf dns-findings
```

Netra never blocks or answers a DNS query differently because of a
finding here — every finding is for operator/SIEM review only.

## Sources

`internal/dnsdetect.Detector.Observe` is fed by a `cmd/netrad` poller
(`internal/dnsdetect.Detector.Run`) that reads the agent's existing
fast-path event stream (`models.AgentReport.Events`) on an interval,
filtering to the matched DNS-response leg — the same precise filter
`netractl explain`'s DNS diagnostics already use
(`Type=="dns-response" && Action=="observed" && Protocol=="UDP" &&
Hook=="cgroup" && Direction=="ingress" && SourcePort==53`) — so a query
and its response are never double-counted, and every observed query
carries a real RCODE. Only the query name, QTYPE, RCODE, and attribution
(namespace/pod/workload/comm) are used; no payload, no answer records.

**QTYPE telemetry:** matched ordinary UDP/53 responses now carry the complete
first question's type. This enables the existing TXT-heavy signal from live
data. Compressed, truncated or oversized questions return zero (unknown).
The event ABI remains 196 bytes; no payload or answer records are retained.
See [Security intelligence and review](security-review.md).

## Why this is stateful

Unlike `internal/sysctlaudit`/`internal/denysim` (pure functions computed
fresh per request), `internal/dnsdetect.Detector` is a long-lived,
mutex-protected object: an LRU of per-`(domain, namespace, pod)` state
(bounded subdomain sets, a sliding 6-minute rate window, a bounded
interval ring for beaconing) that only makes sense accumulated across
many polls. It is constructed once in `cmd/netrad/main.go` and shared
between the background poller (which calls `Observe`) and the API
handler (which calls `Findings`/`Snapshot`) — the same
"long-lived object shared between an HTTP-exposed piece and a
background-running piece" shape `internal/gitops.Reconciler` already
uses. In HA mode it is leader-gated exactly like the GitOps reconciler
and the alert poller: only the active leader's detector accumulates
state, so a failover starts a fresh detector rather than two replicas
disagreeing about it.

## Response shape

`GET /api/v1/ebpf/dns-findings` returns:

```json
{
  "findings": [
    {
      "id": "a1b2c3d4e5f6a7b8",
      "type": "tunneling",
      "severity": "warning",
      "domain": "evil.example",
      "score": 0.75,
      "signals": ["unique-subdomain-count", "high-entropy", "high-query-rate"],
      "namespace": "prod", "pod": "worker-1", "workload": "worker", "comm": "curl",
      "firstSeen": "2026-09-17T10:00:00Z", "lastSeen": "2026-09-17T10:05:00Z",
      "count": 412,
      "exampleNames": ["a1b2c3d4e5f6.evil.example", "f6e5d4c3b2a1.evil.example"]
    }
  ],
  "snapshot": {
    "queriesSeen": 128340, "domainsTracked": 842, "activeFindings": 3,
    "findingsTotal": {"tunneling": 1, "nxdomain_storm": 2}
  }
}
```

`type` is one of `tunneling`, `dga`, `beaconing`, `nxdomain_storm`,
`servfail_storm`. `findings` is TTL-filtered to still-active findings
only; `findingsTotal` in `snapshot` is a lifetime count by type,
including ones that have since expired.

Returns `409` if `NETRA_DNSDETECT_ENABLED` is not set.

## Configuration

```bash
export NETRA_DNSDETECT_ENABLED=true
# optional, all have defaults:
export NETRA_DNSDETECT_INTERVAL=30s
export NETRA_DNSDETECT_MAX_UNIQUE_SUBDOMAINS=200
export NETRA_DNSDETECT_NXDOMAIN_RATIO=0.7
export NETRA_DNSDETECT_SERVFAIL_RATIO=0.7
export NETRA_DNSDETECT_MAX_DOMAINS=50000
export NETRA_DNSDETECT_FINDINGS_TTL=30m
```

| Env var | Default | Notes |
|---|---|---|
| `NETRA_DNSDETECT_ENABLED` | `false` | Gates the whole feature — a plain flag, not a "presence of one value" gate, since every threshold already has a default. |
| `NETRA_DNSDETECT_INTERVAL` | `30s` | Poll interval feeding `Observe`. |
| `NETRA_DNSDETECT_MAX_UNIQUE_SUBDOMAINS` | `200` | Unique-subdomain threshold contributing to a tunneling score. |
| `NETRA_DNSDETECT_NXDOMAIN_RATIO` | `0.7` | NXDOMAIN-ratio threshold for `nxdomain_storm`. |
| `NETRA_DNSDETECT_SERVFAIL_RATIO` | `0.7` | SERVFAIL-ratio threshold for `servfail_storm`. |
| `NETRA_DNSDETECT_MAX_DOMAINS` | `50000` | LRU cap on tracked `(domain, namespace, pod)` keys. |
| `NETRA_DNSDETECT_FINDINGS_TTL` | `30m` | How long an inactive finding stays in `findings` before it's swept. |

Every other `dnsdetect.Config` field (DGA thresholds, beaconing sample
count/jitter, per-domain example cap) keeps its built-in default; they
were judged unlikely to need per-deployment tuning and are not yet
exposed as env vars.

## Scope and attribution

Findings are keyed by `(registered domain, namespace, pod)` — a domain
looked up from two different pods is tracked, and can find, independently
per pod. Attribution (namespace/pod/workload/comm) comes from the
fast-path event's own agent-side enrichment; an event the agent couldn't
attribute to a workload is still counted, just without that detail.

## API and CLI

```text
GET /api/v1/ebpf/dns-findings
netractl ebpf dns-findings
```

MCP tool: `netra_ebpf_dns_findings` (read-only).

## Limits

- **Observe-only.** No enforcement, no answer rewriting, no blocking.
- **Absence of a finding is not proof a domain is benign.** The detector
  only sees matched DNS-response events; a query whose response the
  datapath didn't capture is invisible to it.
- **Heuristic, not exhaustive.** DGA/tunneling scoring is threshold-based
  on entropy/length/digit-ratio signals — tune the thresholds above for
  your environment's actual DNS traffic mix before trusting default
  values in a noisy environment.
- **QTYPE is best-effort** — compressed/truncated questions, TCP DNS and encrypted DNS remain unknown; see **Sources** above.
- **In-memory only.** A `netrad` restart or HA failover resets all
  detector state (LRU, findings, counters) to zero, the same posture
  `docs/snowflake-export.md` already documents for the audit-log
  watermark.
