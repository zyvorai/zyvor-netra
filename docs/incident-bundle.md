# Incident flight recorder bundle (`internal/incidentbundle`)

One portable, redacted, hash-chained file that answers: *what did the network look like on this node in the last N minutes?* It is a read-only view over stores Netra already keeps. It adds no collector, captures no new data and never writes to anything it reads.

```bash
netractl incident bundle --minutes 15 --out incident.json            # JSON
netractl incident bundle --minutes 60 --node worker-1 --mask-ips=prefix --out incident.tar.gz
netractl incident verify incident.json          # offline, fails closed
netractl incident diff before.json after.json   # what differs
curl -H "Authorization: Bearer $TOKEN" "$NETRA_URL/api/v1/incident/bundle?minutes=15&node=worker-1&exclude=audit&mask_ips=ips"
```

MCP tool `netra_incident_bundle` (read-only, available without `NETRA_MCP_ALLOW_MUTATIONS`). Console: **Security, Incident Bundle** (build, inspect, download).

| Parameter | Meaning |
|---|---|
| `minutes` | Window, a whole number from 1 to 1440. Default 15. |
| `node` | Keep one node (cluster-wide audit and lease entries are kept). Letters, digits, `. _ : -`, at most 253 bytes. |
| `exclude` | Comma-separated sections to leave out. They stay in the file as `excluded: true`. |
| `mask_ips` | `ips`: each address becomes `ip-<8 hex>`, a keyed HMAC pseudonym, stable within the bundle. `prefix`: prefix-preserving (Crypto-PAn style); two addresses share an n-bit prefix in the output exactly when they do in the input, family is kept. CIDR lengths are kept. |
| `X-Netra-Mask-Key` header (CLI `--mask-key`) | Optional key (at most 128 bytes) so two bundles use the same pseudonyms and diff cleanly. Without it a random key is drawn and never stored. The bundle records only a key id (first 4 bytes of a hash). |

An unscoped role is required: a bundle spans every namespace on the node, so a namespace-, cluster- or tenant-scoped principal gets 403.

## Format (`netra-incident-bundle/1`)

Top level: `schema`, `generatedAt`, `window` (start, end, minutes), `identity` (product, component, version, scope `cluster|node`, node, mode `observe|enforce`, agents considered and stale), `redaction`, `bounds`, `sections`, `integrity`, `caveats`. Keys are sorted and every list has a fixed sort, so two bundles of the same data are byte-identical apart from `generatedAt`.

| Section | Source store (retention) | Fields |
|---|---|---|
| `nodes` | agent reports (in memory, replaced each report) | node, mode, stale, ageSeconds, startedAt, interface count, hooks, netlink recorder health (available, overruns, missed, dropped), BPF inventory available; `gaps`: every blind spot found (recorder off or overrun, inventory off, stale agent, no agents) |
| `metrics` | per-second tsdb (tier 0 about 1 h, tier 1 about 14 d, tier 2 about 365 d) | 9 key signals (`ebpf.packets`, `ebpf.bandwidth`, `ebpf.kernel_drops`, `ebpf.policy_drops`, `ebpf.tcp_events`, `ebpf.conntrack_entries`, `net.ephemeral_utilization`, `system.cpu`, `mem.used_percent`): context, dimension, units, scope, start, step, up to 120 values (null for gaps), min/max/avg/last |
| `flows` | flow-delta history (7 days, 100000 records) and agent destination counters | top 100 aggregated flows (node, namespace, workload, direction, peer, port, protocol, app protocol, bytes, packets, blocked, retransmissions, first/last seen) and top 50 destinations (packets, bytes, blocked, node count). Aggregates, never packets. |
| `network_changes` | netlink recorder ring on each agent | time, node, kind (link, address, route, neighbor, overrun), action, interface, family, address, destination, gateway, source, state, link type, MTU, table, priority, origin, requester comm/pid/confidence |
| `metadata` | DNS detector (live findings) and agent cumulative counters | DNS findings (type, severity, registered domain, score, signal names, node, workload, first/last seen, count), DNS health rows, TLS SNI handshake counts, HTTP method+host counts, HTTP/1 status counts |
| `ebpf` | agent BPF attachment inventory, cluster fast-path config, deny lease store (history keeps 1000 events) | per-node attached programs (hook, id, name, owner class), attachment findings, deny state as counts per rule kind plus mode, revision, enforce lease, live deny leases, lease changes in the window (create, extend, expire, revoke, reject, rails, break-glass) |
| `audit` | audit trail (last 1000 events) | time, actor, action, target and a fixed allow-list of scalar detail keys |
| `insights` | metric alert engine (bounded history), anomaly model, drop attribution | raised alerts, status transitions in the window, anomaly buckets at or above 20% of samples, drop findings (stage, code, src, dst, packets, explanation) |
| `timeline` | computed from the sections above | time-sorted entries: category, class (change, break, context, state), severity, node, summary and `ref` (`section/list/index`, checked by verify). State entries with no event time (attachment, drop, alert findings) sort last. |

## Redaction by construction

1. **Allow-list.** Each section is a typed Go struct that names the fields allowed in. A field that is not in the struct cannot be emitted; nothing is stripped after the fact by name.
2. **One scrubber for every string.** Control characters become spaces, URLs keep scheme, host and path only (userinfo, query and fragment are dropped), secret-looking text (private-key blocks, bearer and basic tokens, JWTs, AWS and GitHub and Slack tokens, `password=`/`token=`/`api_key=`/`cookie:` style assignments) becomes `[redacted]`, strings are clipped to 300 bytes. Host-like fields (SNI, DNS name, HTTP Host, flow peer) must be plain names or are replaced with `[invalid-hostname]`.
3. **Audit details** keep a fixed key allow-list and scalar values only; the audit actor and action are kept because the audit trail already exposes them.
4. **Never included** (also listed in the bundle's `redaction.neverIncluded`): payload or packet bytes, flow local address, pid or comm on flows, DNS queried subdomain labels and example names (they can carry exfiltrated data), URL paths beyond what a host row needs, query strings, headers, cookies, bodies, MAC addresses, JA3/JA4 hashes, rule values, workload inventory, map contents, argv and environment.
5. `redaction.applied` counts how often each rule fired, `redaction.maskIps` and `maskKeyId` say how addresses were treated, `redaction.excludedSections` lists what was left out.

Hostnames and IPs are kept as the product already exposes them. Masking is opt-in.

## Bounds

Window 1 minute to 24 h. Rows: 60 metric series of 120 points, 100 flows, 50 talkers, 500 netlink events, 50 rows per metadata list, 200 nodes, 200 leases, 200 lease changes, 300 audit entries, 100 alerts, 200 transitions, 200 anomaly buckets, 100 drops, 1000 timeline entries. Total 8 MiB of section data: if over, the largest list is halved (oldest rows first for time-ordered lists) until it fits. Every cut is recorded in the section's `truncated` list (`list`, `total`, `kept`). A request can only lower the bounds.

## Integrity, verify, diff

`integrity` is a sha256 hash chain: a seed over the schema, window, identity and redaction block, then for each section in order `chain = sha256(previous chain || sha256(canonical section JSON))`. It makes tampering and accidental edits visible. It is **not a signature**: whoever can rewrite the file can recompute the chain.

`netractl incident verify FILE` (JSON or `.tar.gz`, exit 1 on any problem) checks: schema version, window and size bounds, every section decoded with unknown fields refused (the allow-list again), payload- and credential-shaped field names, secret-looking strings, over-long strings and opaque encoded blobs, unbounded lists, the hash chain, the excluded flags, timeline refs that point at nothing, and, when `maskIps` is `ips`, any unmasked address. The `.tar.gz` form holds `bundle.json`, `sections/*.json` and `manifest.json` with the sha256 of each member; verify checks the manifest, unlisted members and unsafe paths.

`netractl incident diff A B [--json]` verifies both, then compares section by section. Rows are matched on their non-numeric fields; matched rows whose numbers changed are `changed`, unmatched rows are `added` or `removed`; scalar fields (such as deny counts) are listed old to new. Timestamps that always move (`firstSeen`, `lastSeen`, `since`, `startUnix`) are ignored. Use `--mask-key` on both bundles to compare masked ones.

## Boundaries

- Observe-only. The handler reads the store, tsdb, agent reports and detectors; it never changes a mode, rule, lease, alert or policy, never acks or silences anything and never attaches or detaches a program.
- No payload, argv, environment or Secret contents are collected or carried; no PacketWolf or Paqtra sync is involved.
- It records nothing new: a store that was off, overran or restarted inside the window is a `gaps` entry, not silence. Metadata counters are cumulative since agent start, not windowed.

## Validation

`go test ./internal/incidentbundle ./internal/api -run IncidentBundle ./cmd/netractl` covers a golden bundle for a fixture window (`testdata/golden.json`, rewrite with `-update`), secrets and payload-like fields injected into every store fixture, mask stability and prefix preservation, bounds and truncation, hostile inputs, tamper detection, tar.gz round trip and diff determinism. `web/src/lib/incidentBundle.test.ts` covers the console helpers. `scripts/ci-netractl-live.sh` builds a real bundle from a live controller, verifies and diffs it.

## Seal: keyed attestation (`netra-incident-seal/1`)

The hash chain makes edits visible but is not a signature. For a recipient who shares a key with you, add a detached HMAC seal:

```bash
netractl incident seal incident.json --key-file ./seal.key        # writes incident.json.seal (0600)
netractl incident verify incident.json --seal incident.json.seal --key-file ./seal.key
```

The key (at least 16 bytes) comes from `--key-file` or `NETRA_INCIDENT_SEAL_KEY`, never from an argument, and is never written to the seal or bundle. The seal holds the schema, `hmac-sha256`, the bundle chain head and window, a key id (first 4 bytes of a domain-separated hash), the seal time and the tag. `seal` refuses a bundle that does not verify; `verify --seal` verifies the bundle first, then checks that the seal names this bundle, was made with this key and that the tag matches (constant-time compare). It is symmetric: anyone holding the key can also forge a seal, so it proves "made by a holder of this key", not who. Key distribution and rotation are yours. It works on `.json` and `.tar.gz` bundles, offline.

## Report: an offline incident draft

```bash
netractl incident report incident.json                 # Markdown to stdout
netractl incident report incident.json --json --out report.json
```

The report is derived only from a bundle that verifies, so it adds no data and cannot widen redaction. It gives a verdict (`quiet`, `changes-only` or `breaks`), the first break-class event, the change-class events in the 15 minutes before it (nearest first, at most 10; temporal order, not proof of cause), up to 40 change and break events, up to 12 key signal ranges, deny lease activity and a trust section listing blind spots, excluded or unavailable sections, truncated lists and warning findings without an event time. Output is deterministic for a given bundle. It does not call an LLM and does not contact the controller.

