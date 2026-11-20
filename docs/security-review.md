<!-- SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0 -->
# Security intelligence and review

Netra now offers native DNS QTYPE telemetry, managed threat-feed history,
flat deny-predicate review and temporal security correlation. These are
metadata-based features inspired by enterprise firewall workflows. They
are not a PAN-OS API integration or a claim of full NGFW/IDS/DLP parity.

## DNS query type

The matched UDP/53 response event carries `dnsQType`. The parser requires
one complete, uncompressed first question and IN class, bounded to 96
question-name bytes. Truncated, compressed, oversized or unsupported
questions return zero (unknown). This enables the detector's existing
`txt-heavy` signal when QTYPE=16; a TXT query alone is not an attack.
No answer records or application payloads are retained. Encrypted DNS,
TCP DNS and stream reassembly are outside this parser's scope.

QTYPE consumes two bytes of existing event padding at offset 194. The
packed event remains 196 bytes, all previous offsets stay unchanged,
and old agents simply leave QTYPE zero. No pinned-map ABI changes.

## Feed lifecycle

`PUT /api/v1/intel/feed` accepts the existing JSON, CSV or line list.
IP literals, masked CIDRs and lowercased hostnames are canonicalized before
matching and deduplication. Manual imports return the accepted preview and
skipped entries. Optional `?ttl=1h` sets overall feed expiry (0..720h).
A missing TTL preserves the existing non-expiring operator workflow.
Use `X-Netra-Intel-Revision: N` on PUT, DELETE or rollback for compare-and-set
updates. A revision conflict returns 409 without changing state.

- `GET /api/v1/intel/history`: last 16 revisions, including entry snapshots.
- `POST /api/v1/intel/rollback/{revision}`: append a revision restoring a
  retained snapshot and its original expiry. Expired revisions cannot be
  restored. Rollback never imports entries into deny maps.
- `DELETE /api/v1/intel/feed`: append an empty revision.
- `netractl intel history` / `netractl intel rollback REVISION`.

Expiry removes the feed from live matching and new applications. It does
not revoke already imported deny entries; those retain Netra's existing
leased enforcement behavior. Applying a feed still requires an active
lease and `X-Netra-Confirm-Risk: high`. Feed writes include `auditRecorded`
so operators can see if the separate controller audit write failed.

Set `NETRA_INTEL_STATE_PATH` to an operator-provisioned writable file path
for persistence. The parent directory must already exist. Writes use a
private 0600 temporary file, fsync and atomic rename before publishing in
memory. Invalid/unreadable journals report `journalUnavailable`, leave the
feed empty and refuse updates; repair the journal before writing again.
Memory-only operation remains the default. In HA, put the journal on the
same leader-managed shared persistent storage as controller state.
The journal holds metadata and indicator snapshots, not packet payloads.

## Optional HTTPS refresh

| Environment variable | Default | Meaning |
|---|---|---|
| `NETRA_INTEL_SOURCE_URL` | unset | Explicit operator-configured HTTPS feed; unset disables polling |
| `NETRA_INTEL_REFRESH_INTERVAL` | `15m` | Poll interval, 1m..24h |
| `NETRA_INTEL_TTL` | `1h` | Expiry after a successful refresh, at least twice the interval, at most 720h |

Refresh runs immediately then on the interval, only during a controller
leader stint in HA. Demotion cancels and waits for the poller. TLS uses
normal certificate validation. Redirects, URL userinfo and fragments are
rejected. Fetches have a 15s timeout and 1 MiB body limit. Empty, malformed,
partially parsed, duplicate, truncated and over-cap feeds retain the last
good revision. Revision compare-and-set prevents a download from replacing
an intervening operator update. Query strings are stripped from persisted
provenance; public errors do not echo URLs or remote bodies. Only configure
trusted feed URLs; this downloader does not discover or crawl sources.
`lastRefresh` / `refreshError` show the most recent attempt. Refresh never
applies firewall rules, changes mode, or extends an enforcement lease.

## Deny-predicate review

`GET /api/v1/security/optimizer` / `netractl security optimizer` reports
IP, CIDR and port predicates with equivalent, covered or overlapping
predicate suggestions. Addresses/families, directions, protocols and TCP
SYN restrictions are considered. Suggestions are capped at 200 and the
review at the first 1,000 predicates; `truncated` makes limits
visible. Current configuration is not changed.

`matchingEvents` counts fresh sampled agent events within ten minutes,
excluding stale reports. Port predicates use the packet destination port,
as the datapath does. Counts are not winning-rule hits or evidence that a
rule is unused. Allow exceptions, native NetPol, workload scope, conntrack,
hook order and the enforcement lease can change actual outcomes. TCP SYN
restrictions vary by hook; the sampler accounts for their cgroup/TC check.
There is no automatic deletion or policy-precedence proof.

## Security correlation

`GET /api/v1/security/incidents` / `netractl security incidents` joins
recent DNS findings, scan findings and dated agent events matching active
IP/CIDR feed entries. It requires exact node/namespace/pod attribution,
a non-stale reporting node, timestamps in the past ten minutes and at least
two different evidence kinds. Unknown attribution, future timestamps and
stale evidence are excluded. This is temporal correlation, not proof of
causality or an attack. It does not invent timestamps for aggregate counters.
DNS/SNI feed matches remain available through their existing APIs.

IDs and ordering are deterministic. Output is capped at 200 incidents and
50 evidence items per incident while retaining each independent kind;
`truncated` is explicit. Detector-enabled flags distinguish disabled
sensors from an empty result. No quarantine or deny is automatically applied.

The dashboard exposes **Security → Security Review**, with feed history,
rule review, independent evidence and refresh/error states. MCP tools
`netra_security_optimizer`, `netra_security_incidents` and
`netra_intel_history` are always read-only. No mutation tools were added.
