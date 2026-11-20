# Sampled L7 protocol observation

Which **Redis commands, SQL verbs, Kafka APIs and gRPC methods** a workload uses, and how
often they fail, without a proxy, a sidecar, or storing any traffic. A small `cgroup_skb`
program copies the first bytes of TCP segments to or from a **configured service port**
into a ring buffer; the agent classifies them into a bounded set of operation names and
throws the bytes away.

It is **off by default**, because it reads application payload bytes. Turn it on
deliberately (`NETRA_L7_SAMPLE=auto`, Helm `agent.l7Sample`).

## What leaves the agent, and what never does

Privacy is a property of the output, not a promise about the input. Every field the parser
can return is an allowlisted operation name, a coarse outcome, or a validated pattern:

| Protocol | Reported | Read only to classify, never kept or exported |
|---|---|---|
| Redis | command (`GET`, `SET`, …, else `OTHER`); reply kind and error kind (`ERR`, `WRONGTYPE`, …) | keys, values, arguments |
| PostgreSQL | SQL verb (`SELECT`, `INSERT`, …, else `OTHER`); message kind; SQLSTATE **class** (two characters) | SQL text, parameters, passwords, error messages |
| MySQL | command; SQL verb; error **class** (`access_denied`, `syntax`, …) | SQL text, credentials, error text |
| Kafka | request API name (`Produce`, `Fetch`, …) | topics, keys, payload, client id |
| HTTP/2 + gRPC | `:method`; for gRPC the `/package.Service/Method` path (only if it matches that shape); `:status` / `grpc-status` | other paths, query strings, authorization and cookie headers, bodies |
| HTTP/1 | method, status, and the `Host` (validated as a hostname, bounded to 200 distinct pairs) | request target, query string, cookies, bodies |

Tests enforce this rather than assert it:

- A secret is planted in a Redis key, SQL text, a gRPC path, a cookie, a bearer token and an
  error message for every protocol; it must never appear in any output field.
- Over 200 000 random and mutated inputs (and a fuzz target CI runs for 20 seconds) every
  label must be from an allowlist or a validated pattern, so the cardinality of a metric built
  from it is bounded by construction; nothing may panic.
- The end-to-end smoke test runs the real agent and controller and asserts that a planted
  secret appears **nowhere** the stack exposes: not in `/api/v1/l7/sampled`, not in the
  agent's own report, not in `/metrics`, not in either process's log.

The payload exists in the agent's memory only between the ring buffer and the parser. It is
not written to disk, logged, or sent to the controller.

## Roles: served and issued

A request crosses the wire twice: leaving its client (egress) and arriving at its server
(ingress). Counting both would double every request, so counts carry a **role**:

- `served`: what this node's **services** handled (requests arriving, responses leaving);
- `issued`: what this node's **workloads** asked of others (requests leaving, responses
  arriving).

Sum a role across nodes; **never add the two roles together**. On one node talking to itself
(loopback) both roles see the same traffic, which is why the end-to-end test expects, for
example, 30 `GET`s in each role for 30 sent.

## Sampling, and turning samples into estimates

Only segments that carry payload and touch a configured port are eligible. Each flow and
direction is limited to one sample per `NETRA_L7_SAMPLE_GAP` (default 100 ms), so a hot
connection cannot swamp the ring buffer. The kernel counts what it saw and what it sent up:

- `eligible`: payload-bearing segments on a configured port;
- `emitted`: sampled and sent to the agent;
- `rateLimited`, `ringbufFull`, `loadFail`: why the rest were not (they add up: eligible =
  emitted + rateLimited + ringbufFull + loadFail).

`scaleFactor = eligible / emitted` converts a sampled count into an estimate of the real one
(`/api/v1/l7/sampled` returns both `count` and `estimated`, scaling each node by its own
ratio). It is an estimate: rare operations may be missed entirely and any one operation's
share is only as good as the sample. With the rate limit off (`0s`) every segment is sampled
and counts are exact, which is how the tests pin them.

## Enabling

| Variable (agent) | Default | Meaning |
|---|---|---|
| `NETRA_L7_SAMPLE` | `off` | `off` · `auto` (degrade, reporting why) · `required` (fail startup) |
| `NETRA_L7_SAMPLE_PORTS` | `6379:redis,5432:postgres,3306:mysql,9092:kafka,50051:grpc` | `port:protocol,…` with `redis`, `postgres`, `mysql`, `kafka`, `http2`/`grpc`, `http1` (at most 60) |
| `NETRA_L7_SAMPLE_GAP` | `100ms` | minimum time between samples of one flow and direction; `0s` samples everything |
| `NETRA_BPF_L7SAMPLE_OBJECT` | `/opt/netra/bpf/netra_l7sample.o` | compiled object |

Helm: `agent.l7Sample`, `agent.l7SamplePorts`, `agent.l7SampleGap`. A bad port list is
reported (`unavailable`) rather than silently sampling less than asked for. It needs the
cgroup hierarchy (`agent.cgroupEnabled`).

## Reading it

```
GET /api/v1/l7/sampled?protocol=redis&node=worker-1        # viewer role
```

Per protocol and role: requests, responses, errors, undecodable header blocks, the busiest
operations (at most 50 after merging nodes, the rest folded into `OTHER`), and response
codes; plus a bounded `hosts` list for HTTP (per role). `nodes[]` says which agents sample and, for one
that could not start, why.

`/metrics` (labels are protocol, role and an allowlisted operation or code; no hosts,
addresses or payload text):

| Series | Meaning |
|---|---|
| `netra_l7_sample_nodes_reporting` / `_not_reporting` | agents sampling / not |
| `netra_l7_sample_scale_factor` | cluster `eligible/emitted` |
| `netra_l7_sample_requests{protocol,role,op}` | sampled requests |
| `netra_l7_sample_responses{protocol,role,status}` | sampled responses, ok vs error |
| `netra_l7_sample_error_codes{protocol,role,code}` | error kinds |
| `netra_l7_sample_undecodable{protocol,role}` | HTTP/2 header blocks that could not be decoded |

Values are sampled counts (multiply by the scale factor for an estimate), gauges of per-agent
running totals: an agent restart resets its contribution.

## Cost

The program runs on every TCP segment in the attached cgroup, so its cost is per packet, not
per event. Measured with the kernel's own BPF accounting on a 4-vCPU aarch64 VM (Linux 6.8):
about **29 ns per program run** for traffic to a port that is *not* configured (a header parse
and two map lookups; the common case) and about **65 ns** on a configured port with the default
rate limit (mostly rate-limited). An emitted sample adds a payload copy and a ring-buffer write,
at most ten per second per flow and direction at the default. Caveats: loopback, not a NIC under
load; the accounting adds a little; `TestL7SampleCostPerPacket` re-measures this in CI and fails
on an order-of-magnitude regression (over 30 µs per packet).

## Limits

- **Plaintext only.** TLS traffic is not readable at this layer; a Redis or Postgres session
  inside TLS shows only its handshake. HTTPS specifically can be covered by the separate,
  explicitly opt-in [`tls-plaintext.md`](tls-plaintext.md), which reads it at OpenSSL instead.
- **A sample is a fragment, not a stream.** Parsers are stateless and best-effort; a message that
  does not start where the sample does, or that spans packets, may not classify.
- **HTTP/2 header compression is stateful per connection.** The first `HEADERS` on a connection
  decodes; a later one that references dynamic-table entries the sample never saw cannot, and is
  counted as `undecodable_headers`, not guessed. Long-lived gRPC connections therefore yield
  fewer method names than short ones; `undecodable` says by how much.
- **Kafka responses are not classified** (they carry only a correlation id; the request they
  answer needs connection state), and **MySQL** handshake/login packets are not.
- **Only configured ports**, TCP only, IPv4 and IPv6. A service on a non-standard port must be
  listed. Other traffic on a configured port that does not parse is counted as unclassified.
- **Ring-buffer pressure:** if the agent cannot keep up, samples are dropped and counted
  (`ringbufFull`), which lowers `emitted` and raises the scale factor accordingly.
- **Both roles of one node overlap on loopback**, as described above.

## Verification

- `./scripts/ci-l7sample-unit.sh` (CI job `go`): parsers, event decoder, bounded counters,
  the leak and bounded-label properties, `-race`, and a 20 s fuzz; asserts a minimum test count.
- `./scripts/ci-ebpf-tests.sh` (CI job `ebpf`, root): the real object in the real verifier
  and real loopback TCP: Redis request and reply captured in both directions and classified;
  **every payload length from 1 to 140 bytes captured exactly** (this guards the chunked copy
  and the compiler-opaque bounds checks the verifier needs; the first version was rejected by the
  real verifier); ports not configured are ignored; the rate limiter's counters add up; IPv6
  Postgres; payload-less segments ignored. The step fails on a skip.
- `./scripts/ci-l7sample-smoke.sh` (CI job `l7sample-smoke`, root): the real agent and controller
  with fake Redis and PostgreSQL servers: exact per-role operation and error counts through the API
  and `/metrics`, the kernel counters, and the no-secret-anywhere check.
- The object is compiled in the agent image, and the image gate requires it.

Run on Ubuntu 24.04 (Linux 6.8, aarch64) and the GitHub Actions runner (Linux 6.17, x86_64). Not yet
run in a Kubernetes pod on a live node. MySQL and Kafka are verified against bytes constructed from
their protocol specifications, not against a live server.
