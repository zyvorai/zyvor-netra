# Flow history, RED, traces

The live Connections page is still a short sample. This is the longer
view, built from the same agent destination counters. No payloads, no
argv, no pod labels on Prometheus.

## History

`GET /api/v1/flows/history` and `netractl flows history`.

Each record is a **delta** since the previous report for one
node, pod, peer, port, and protocol: packets, bytes, blocked,
retransmissions, RTOs, and the latest TCP SRTT. The first time a flow
is seen it only sets a baseline, so it does not appear until the next
report.

Default retention is 7 days and 100 000 records. The controller writes
them to a sidecar next to the state file (`<state>.flows`). A restart
loads that file. The baseline map is not stored, so the first report
after a restart does not emit a delta. This is not a column store.

Filters: `since` (`1h` or RFC3339, max 168h), `namespace`, `pod`, `peer`,
`protocol`, `app`, `node`, `limit` (max 2000).

`app` / `appProtocol` is a well-known-port hint: mysql 3306, postgres
5432, redis 6379, kafka 9092, grpc 50051, http 80/8080, https 443.
gRPC on 443 is labeled https. Nothing in the payload is parsed.

`comm` and `pid` are copied when TCP health has a live owner for that
peer and port. Stale ownership is not copied. No cmdline.

`dnsName` and `tlsSni` are best-effort joins from the same agent report
(DNS events and TLS metadata). Empty means unobserved — never invented.
Historical deny preview uses these fields when present.

The console Flows page shows the last hour, a RED table, and inferred
paths.

## RED

`GET /api/v1/insights/red?window=5m` and `netractl insights red 5m`.

| | Source |
|---|---|
| Rate | Flow packet deltas / window |
| Errors | Blocked + retransmission + RTO deltas |
| Duration | Average TCP SRTT, weighted by packets |

DNS failure counts and HTTP request counts on the same row are the
latest cumulative agent counters, not window deltas. Cleartext HTTP/1
5xx counts are a separate `http5xx` field, also cumulative, and only
when the status line starts the packet. HTTP/2 and HTTP/3 are not
decoded.

## Traces

`GET /api/v1/insights/traces?since=15m` and `netractl insights traces 15m`.

Each recent flow is a span. If the peer IP belongs to a pod, that
pod's next egress within 5 seconds is a child. The link is a guess.
No `traceparent` is read or written. This is separate from SIEM
`format=otlp-trace`, which is still one span per blocked event.

Pod IPs come from the Kubernetes API. Without it, spans are not linked.

## Profiles

`GET /api/v1/insights/profiles` and `netractl insights profiles`.

Kernel stacks from `/proc/<pid>/stack` for up to five hottest host
comms on the latest agent tick, plus `wchan` (the kernel wait channel,
one symbol). Not a user-space flame graph. Not on
`GET /api/v1/node-resources`. A sample is kept when the stack is
unreadable if `wchan` is set. `wchan` of `0` means not waiting and is
omitted.

## Workload events

`GET /api/v1/insights/workload-events` and
`netractl insights workload-events [namespace] [pod]`.

Kubernetes `Warning` events whose involved object is a Pod. The
controller ClusterRole lists `events`. The application journal is not
read. Messages that look like credentials are dropped; the reason
remains.

## Kernel notes

`GET /api/v1/insights/kernel-notes` and `netractl insights kernel-notes`.

A bounded tail of kernel log lines about netdev, TCP, UDP, conntrack,
and OOM, read from the node's `/dev/kmsg`. The agent DaemonSet mounts
that device read-only. Credential-like lines are dropped. This is not
`journalctl` and not a full `dmesg` dump. MCP: `netra_insights_kernel_notes`.

## Prometheus

`netra_flowlog_records` counts retained deltas. It has no pod or
destination label. High-cardinality questions go to the history API.

## Linux smoke

`scripts/ci-flow-observe-veth.sh` (Linux, root) stands up a veth, runs
iperf3 TCP on port 3306, and posts two agent reports whose packet and
byte counters are that interface's RX counters. It then checks, in
order, history, RED, the mysql port hint, comm/pid, an inferred span,
a `/proc/<pid>/stack` profile, the workload-events contract (no
Kubernetes client in this process, so `available` is false), and that
`netra_flowlog_records` has no pod label.

```bash
sudo ./scripts/ci-flow-observe-veth.sh
# Optional: sudo CONTROLLER_PORT=31980 ./scripts/ci-flow-observe-veth.sh
```

GitHub job: `flow-observe-veth`. This smoke does not load the eBPF
agent. It exercises the controller path a node agent uses when it
reports. The port hint is not a MySQL parser; the bytes are iperf3.

### Lab, 2026-09-18 (NLDW4-4-16-36)

One run, all eight steps passed. veth `netra-obs0`, peer `10.255.78.2`,
iperf3 port 3306, pid 3494291, comm `iperf3`. RX moved from 1 packet to
87. History stored the delta of 86 packets and 6084 bytes, RED rate was
non-zero, `appProtocol` was `mysql`, the trace span was inferred, the
profile had 7 kernel frames, workload-events reported `available=false`
(this netrad had no Kubernetes client), and `netra_flowlog_records` was
`1` with no labels. After the same host's controller rollout, the
deployed APIs were live: history matched 1215 flows, RED had 30
workloads, traces returned 200 spans, profiles returned 1 stack, and
workload-events was available with 41 pod warnings. `netra_flowlog_records`
was 1215 with no labels.

## See also

- [competitive-observability.md](competitive-observability.md)
- [l7-metadata.md](l7-metadata.md)
- [experience.md](experience.md)
- [investigation-ux.md](investigation-ux.md)
