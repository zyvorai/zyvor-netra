# eBPF observability → Netra gaps

Internal product strategy. Compares Netra to products that do the same
job: Cilium Hubble, Microsoft Retina, Red Hat Network Observability,
Pixie, DeepFlow, Grafana Beyla, Coroot, Tetragon, commercial network
performance monitoring (Datadog NPM, Kentik), and per-second infrastructure
monitoring (Netdata).

Not versus cloud SSE or perimeter NGFW. Those are already non-goals in
[`competitive-sse.md`](competitive-sse.md) and
[`competitive-quantum.md`](competitive-quantum.md).

## Positioning

| | **eBPF NPM / APM class** | **Netra (today)** |
|---|---|---|
| Job | Stored flows, request metrics, sometimes traces and profiles | Live observe + node-stack diagnostics + leased emergency deny |
| History | Hours or days of filterable flows (Relay, Loki, ClickHouse) | 7-day flow sidecar next to controller state, queryable by pod/peer/port. Not a column store |
| L7 | HTTP status, gRPC, Kafka, Redis, SQL | HTTP/1 Host, cleartext HTTP/1 status when the status line starts the packet, TLS SNI, DNS health, QUIC flag, plus a well-known-port hint (mysql, postgres, redis, kafka, grpc) |
| Process | A process on each connection | Comm and pid on a flow when TCP health matches that peer and port. No argv |
| Payload | Some products keep bodies | Explicitly **no** payloads, argv, Secrets |

Netra is not empty. It already has live flows, DNS and TLS metadata,
JA3/JA4, TCP health, connect latency, path and congestion boards, drop
reasons, qdisc and softnet counters, a workload experience score, and a
drop-incident context (node, CPU, memory, comm-only processes) beside a
PCAP. The section below is what used to be missing, and what is still
refused.

### Versus Netdata

| | **Netdata** | **Netra metrics platform** |
|---|---|---|
| Resolution | Per second, zero config | Per second, zero config ([`metrics.md`](metrics.md)) |
| Storage | dbengine tiers on each agent and parent | Tier 0 on the agent (also the replay buffer); tiers 0/1/2 per node on netrad |
| Collectors | Hundreds of plugins: host, containers, apps, databases, SNMP | Host, network stack, conntrack, cgroups, process groups, eBPF datapath, workload RED, nine app kinds plus any Prometheus endpoint ([`app-collectors.md`](app-collectors.md)) |
| Databases | Native PostgreSQL, MySQL and more | Through postgres_exporter / mysqld_exporter; no driver or DB credentials in the agent |
| ML | Per-dimension k-means, anomaly rate, metric correlations | Same approach in stdlib Go, plus KS-based "what changed" ([`anomaly-detection.md`](anomaly-detection.md)) |
| Alerts | Health config language, hundreds of stock alerts | Netdata-style rule YAML and expressions, over 40 stock rules including workload RED and eBPF drops ([`metric-alerts.md`](metric-alerts.md)) |
| Process view | apps.plugin groups by process name and command line | Groups by kernel comm only; never argv, cmdline or environ |
| Network evidence | Charts only | A chart window links to flows, drop reasons, TCP/DNS/HTTP boards and captures from the same eBPF datapath |
| Workload context | Container and cgroup charts | Per-workload RED series from datapath counters, alerted and scored with no configuration |
| Fleet | Netdata Cloud (SaaS) or parents | netrad per cluster plus a read-only roll-up across `NETRA_FLEET_PEERS` |
| Control | None (monitoring only) | Monitoring stays read-only; separate leased emergency enforcement |

Netdata still wins on collector breadth, native database and SNMP
collectors, and long-standing stock alert tuning. Netra's metrics are the
host baseline joined to network evidence, not a replacement for every
Netdata plugin.

## Where Netra is already stronger

- Node stack forensics: softnet, qdisc, sysctl audit, kernel drop reason
  names. Hubble-class tools show policy drops. They do not freeze host
  CPU, memory, and process tops beside the packets. See
  [`tutorials/drop-incident-context.md`](tutorials/drop-incident-context.md).
- Observe-first plus a leased emergency control, without taking over
  Cilium maps.
- Encrypted-traffic intel without decrypt (JA3/JA4, ECH, DoH/DoT).

## What closed

These used to be the holes. Each one is now a read API. The limits under
each item are still true.

### 1. Queryable flow history

`GET /api/v1/flows/history` and `netractl flows history` keep pod, peer,
port, protocol, bytes, and drops for 7 days (100 000 deltas) in a
sidecar file next to the controller state. The first sample of a flow
is a baseline and is not stored. The baseline map itself is not in the
file, so the first report after a restart starts a new baseline. It is
not ClickHouse. See
[`flow-log.md`](flow-log.md). Linux smoke:
`scripts/ci-flow-observe-veth.sh` (GitHub job `flow-observe-veth`).
The live Connections sample is unchanged.

### 2. Per-workload RED

`GET /api/v1/insights/red` and `netractl insights red` give rate, errors,
and duration per workload over a window. Rate is flow deltas. Errors are
blocked packets plus TCP retransmission and RTO deltas. Duration is
average TCP SRTT. Cleartext HTTP/1 status is counted when `HTTP/1.x NNN`
starts the packet (`GET /api/v1/ebpf/l7` field `httpStatus`, RED
`http5xx`). HTTP/2, HTTP/3, and a status line split across packets are
still invisible ([`l7-metadata.md`](l7-metadata.md)).

### 3. Protocol labels beyond HTTP Host

A flow record carries `appProtocol` when the destination port is a
well-known mysql, postgres, redis, kafka, amqp, mongodb, grpc (50051),
http, or https port. That is a hint, not a parser. gRPC on 443 stays
`https`. Payload decode of those protocols was not added.

### 4. Process on the flow

When TCP health has a live pid and comm for the same peer and port, the
flow record copies them. Process metadata comm fills a gap if TCP health
has a pid and no comm. No argv, no cmdline. Kernel `kfree_skb` drops
stay reason counts with no 5-tuple ([`drop-diagnostics.md`](drop-diagnostics.md)).

### 5. Service-path traces

`GET /api/v1/insights/traces` builds spans from flow edges. If the peer
IP is a known pod, that pod's next egress within 5 seconds becomes a
child span. This is inferred and can be wrong. No traceparent is
propagated. `format=otlp-trace` is still one parentless span per blocked
event ([`siem-export.md`](siem-export.md)).

### 6. Bounded kernel stack

`GET /api/v1/insights/profiles` returns `/proc/<pid>/stack` for the top
CPU comms on the latest agent tick (at most five, depth 16). Kernel
frames only, plus `wchan` when the process is waiting in the kernel.
Not a continuous user-space flame graph. A PID is skipped when both
the stack and `wchan` are empty. Not on `GET /api/v1/node-resources`.

### 7. Kubernetes Warning events

`GET /api/v1/insights/workload-events` lists Pod warnings (OOMKilled,
Unhealthy, BackOff, Failed, and any other `type=Warning`). The
controller role can list `events`. The application journal is still not
collected. `GET /api/v1/insights/kernel-notes` keeps a scrubbed tail of
kernel lines about netdev, TCP, UDP, conntrack, and OOM — not a dmesg
dump. A message that contains password, secret, token, bearer, or
authorization is omitted.

### 8. High cardinality stays off Prometheus

`netra_flowlog_records` is one gauge with no pod or destination labels.
Filterable history is the flow API, not the metrics scrape.

## Still not done

- HTTP/2, HTTP/3, TCP reassembly, and any HTTP status line that does not start the packet.
- Flow history past 7 days, or a column-store warehouse.
- User-space CPU flame graphs (`wchan` is one kernel wait symbol, not a graph).
- Application journal collection (kernel-net and OOM lines only).

## Leave alone

Decrypting to inspect or store content, DLP, argv/cmdline, payload bodies, ZTNA, and a
cloud proxy. Pixie and SSE products win those by collecting what Netra refuses. Copying them
would break the boundary in [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

One deliberate, opt-in exception to "no decrypt": [`tls-plaintext.md`](tls-plaintext.md) reads
application plaintext at OpenSSL's `SSL_write`/`SSL_read` so HTTPS gets the same bounded operation
counts as [`l7-sampling.md`](l7-sampling.md). It is off by default, can be limited to named
processes in the kernel, and exports only method, host and status: never a path, header, cookie,
token or body. It does not intercept TLS, hold keys, or store content.

PacketWolf remains the Cilium-side durable policy and Hubble consumer.
Netra should not grow a second Hubble. See [`packetwolf.md`](packetwolf.md).

## See also

- [flow-log.md](flow-log.md) — queryable flow history, RED, traces
- [metrics.md](metrics.md) — per-second metrics, anomalies, metric alerts
- [p0-p5-surfaces.md](p0-p5-surfaces.md) — shipped observe catalog
- [competitive-sse.md](competitive-sse.md) — cloud SSE / Zero Trust, out of scope
- [competitive-quantum.md](competitive-quantum.md) — perimeter NGFW, out of scope
- [investigation-ux.md](investigation-ux.md) — live connection sample
- [l7-metadata.md](l7-metadata.md) — what L7 is and is not
- [experience.md](experience.md) — workload score, not APM
- [tutorials/drop-incident-context.md](tutorials/drop-incident-context.md) — host snapshot at drop time
