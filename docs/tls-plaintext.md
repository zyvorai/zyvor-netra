# TLS plaintext sampling (OpenSSL uprobes)

For HTTPS, the packet-level sampler ([`l7-sampling.md`](l7-sampling.md)) sees only
ciphertext. This feature reads the same **bounded metadata** (HTTP method, host, status;
HTTP/2 and gRPC operation names) one layer up: at the point where an application hands bytes
to OpenSSL's `SSL_write` and gets them back from `SSL_read`, by attaching uprobes to the
library.

> **This is a change of stance, and it is opt-in.** Netra's documented boundary has been
> "no decrypt". That still holds by default and for everything else Netra does. This feature is
> the one deliberate, explicit exception: with `NETRA_TLS_UPROBES` on, the agent's kernel
> program **reads plaintext** in the memory of the processes you allow. What that means, what
> it does not mean, and how to limit it are set out below. It is off unless you turn it on.

## What it is, precisely

- It is **not** TLS interception. No keys, no certificates, no proxy, no man-in-the-middle, and
  nothing is decrypted by Netra: the application decrypts its own traffic, and the probe copies
  the first 128 bytes of what it was handed or returned.
- It is **not** DLP, and it exports no content. Those bytes go from the kernel to the agent's memory,
  are classified, and are discarded. They are never written to disk, logged, or sent to the
  controller.
- What leaves the agent is the same allowlisted vocabulary as the packet-level sampler: an
  operation name and a coarse outcome. **Never** a path, query string, header, cookie, bearer
  token, or body.

| Protocol | Reported | Read only to classify, never kept or exported |
|---|---|---|
| HTTP/1 | method, status code, `Host` (validated as a hostname; at most 200 distinct pairs) | request target, query string, cookies, authorization, bodies |
| HTTP/2 + gRPC | `:method`; for gRPC the `/package.Service/Method` path (only if it has that shape); `:status` / `grpc-status` | other paths, query strings, authorization and cookie headers, bodies |

Tests enforce this rather than assert it. The end-to-end smoke test runs real HTTPS between real
processes with secrets planted in the **URL path, the query string, a cookie and a bearer token**;
none may appear in `/api/v1/l7/tls`, in the agent's own report, in `/metrics`, or in either process's
log. The classifier's unit tests require the same of every result.

## Limiting what it can see

Set an allowlist and the kernel program checks the process name **before copying a single byte**:

```
NETRA_TLS_UPROBES_COMMS=nginx,envoy          # Helm: agent.tlsUprobesComms
```

A process not on the list is counted (`commFiltered`) and never read; a test proves that no event is
produced for it and that the calls are counted as filtered rather than sampled. Empty means every
process that uses libssl, so on a shared node an allowlist is the responsible default.

## Enabling

| Variable (agent) | Default | Meaning |
|---|---|---|
| `NETRA_TLS_UPROBES` | `off` | `off` · `auto` (degrade, reporting why) · `required` (fail startup) |
| `NETRA_TLS_UPROBES_COMMS` | (all) | comma-separated process names to observe, enforced in the kernel |
| `NETRA_TLS_UPROBES_GAP` | `100ms` | minimum time between samples of one connection and direction; `0s` samples everything |
| `NETRA_TLS_UPROBES_RESCAN` | `30s` | how often to look for libraries in newly started processes |
| `NETRA_BPF_SSL_OBJECT` | `/opt/netra/bpf/netra_ssl.o` | compiled object |

Helm: `agent.tlsUprobes`, `agent.tlsUprobesComms`, `agent.tlsUprobesGap`. Enabling it sets
**`hostPID: true`** on the agent DaemonSet, because finding other workloads' libraries means
reading the host's `/proc/<pid>/maps`. That is a real widening of what the (already privileged)
agent can see, so the chart renders it only when this or process metadata is on, and CI asserts
that a default render has neither.

## How it works

`bpf/netra_ssl.c` attaches to `SSL_write`, `SSL_read`, and the `_ex` variants (`SSL_write_ex`,
`SSL_read_ex`, which CPython and many others call). A write is sampled at entry, when the plaintext
is in the caller's buffer; a read is sampled on return, when it has been filled. The agent scans
`/proc/*/maps` for `libssl.so*`, attaches once per distinct file (by device and inode: a uprobe
applies to every process that maps that inode, including ones started later and ones in containers,
which are reached through `/proc/<pid>/root`), and rescans for new ones.

One object serves x86_64 and arm64: the argument registers sit at different offsets of the saved
`pt_regs` on each, so the agent writes those offsets into the program's read-only data at load
time from the running architecture. Both are verified on real kernels in CI.

Which side a process is on is inferred from what it did: writing a request or reading a response
makes it a client (`role=issued`), reading a request or writing a response makes it a server
(`role=served`). As in the packet-level sampler, each request is seen once in each role and the two
roles must be summed separately, never together.

## Reading it

```
GET /api/v1/l7/tls?protocol=http1&node=worker-1        # viewer role
```

The same view as `/api/v1/l7/sampled`, for TLS: per protocol and role, requests, responses, errors,
the busiest operations and response codes, a bounded host table (per role), the instrumented
`libraries` per node, and the kernel counters. `/metrics` has the `netra_tls_sample_*` family, with
the same bounded labels (`protocol`, `role`, and an allowlisted operation or code; no hosts, paths
or libraries).

`eligible` counts calls that carried data **from an observed process**; `emitted` is how many were
sampled. They add up (`eligible = emitted + rateLimited + ringbufFull + readFail`), so
`scaleFactor = eligible/emitted` is the true sampling factor and is exactly 1 when the rate limit is
off. Calls skipped by the allowlist are in `commFiltered`, not in `eligible`.

## Cost, measured

A uprobe traps into the kernel on every `SSL_read`/`SSL_write` of every process that maps the
library, so this costs more per call than the packet-level program. Measured with the kernel's BPF
accounting on real GitHub runners running real HTTPS between Python processes (a new TLS connection
per request, so each request includes a handshake):

| | x86_64 (Linux 6.17) | arm64 (Linux 6.17) |
|---|---|---|
| program run time per probe | about 1.0 µs | about 1.4 µs |
| per HTTPS request, without / with the sampler | 3.15 ms / 3.24 ms | 3.02 ms / 3.13 ms |

That is roughly 3 to 4% on a request that includes a full handshake, and includes the trap itself
(around 9 probe runs per request). Caveats: loopback, shared CI runners, one client library; a
long-lived connection making many small calls pays the per-call cost each time, which the rate limit
does not remove (it limits *samples*, not probe entries). `TestSSLCostPerCall` re-measures this in CI
and fails on an order-of-magnitude regression (over 50 µs per run).

## Limits

- **Dynamically linked OpenSSL only** (`libssl.so.*`, 1.1 and 3). It cannot see a **statically linked**
  OpenSSL (many nginx builds, some containers), Go's `crypto/tls`, BoringSSL or LibreSSL builds that
  do not export these symbols, NSS, GnuTLS, or Java and Node's bundled stacks. A process using one of
  those is simply not observed.
- **A sample is a fragment.** Only the first 128 bytes of a call are read, classified statelessly;
  HTTP/2 header compression is stateful per connection, so a `HEADERS` block that references state the
  sample never saw is reported as `undecodable_headers`, not guessed (see `l7-sampling.md`).
- **HTTP/1 and HTTP/2 only.** Other protocols carried over TLS are not classified here.
- **Needs the host's `/proc`** (hostPID in Kubernetes) and root; the agent already has the latter.
  Libraries in a container are reached through `/proc/<pid>/root`, which needs that process to be
  visible.
- **x86_64 and arm64.** Other architectures are refused with a reason rather than guessed at.
- **Sampling, not events:** counts are estimates; scale with `scaleFactor`.
- It sees what the *application* handles, so a process that never calls `SSL_read`/`SSL_write` (for
  example one using kernel TLS offload) is not visible.

## Verification

- `./scripts/ci-sslprobe-unit.sh` (CI job `go`): register layouts for both architectures, the event
  decoder, libssl discovery (one attach per distinct file across processes and containers; deleted and
  lookalike libraries ignored), classification and role inference, that no request text reaches a
  result, the agent's modes, the separate TLS API view and metric family.
- `./scripts/ci-ebpf-tests.sh` (CI jobs `ebpf` and **`ebpf-arm64`**): the real object in the real
  verifier, uprobes on the system's real libssl, and genuine TLS between a Python HTTPS server and
  client: the request and response captured in plaintext (and nothing shaped like a TLS record),
  exact per-role counts, exact status counts, the process allowlist enforced in the kernel, the rate
  limiter's counters adding up, and the cost. The step fails on a skip.
- `./scripts/ci-tlssample-smoke.sh` (CI job `tlssample-smoke`): the real agent and controller, real
  HTTPS, exact per-role method, status and host counts, the kernel counters, and the no-secret-anywhere
  check with secrets in the path, query string, cookie and bearer token.

Run on real GitHub Actions kernels (Linux 6.17, x86_64 and arm64, OpenSSL 3.0.13). Not yet run in a
Kubernetes pod on a live node.
