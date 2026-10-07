# Netra L7 metadata — v0.10

Netra v0.10 adds metadata-only application context to the standalone eBPF datapath without turning Netra into a payload-capture or stream-DPI system.

## TLS SNI

On cgroup egress TCP traffic Netra looks for an ordinary TLS ClientHello and, when the Server Name Indication extension is fully present in the current skb, records only the normalized SNI hostname plus cgroup/workload attribution and counters. It reads the first 640 payload bytes of the skb, and the extension must start within its first 512.

The parser is deliberately best-effort. Netra does **not** perform TCP stream reassembly. A ClientHello split across skbs, TLS Encrypted ClientHello (ECH), QUIC/HTTP3, or an unsupported layout can be invisible to the SNI parser. No TLS keys, certificates, application records, or payload bytes are exported.

Exact SNI rules are an emergency containment layer. They are evaluated only after a hostname was successfully parsed and only while the normal Netra enforcement lease is active. Failure to parse means the SNI-specific control fails open; IP/CIDR/L4/process/UID controls still apply independently.

Maps:

- `tls_sni_stats`: cgroup + SNI → handshakes / SNI-blocked / last seen.
- `blocked_sni`: exact normalized hostnames staged by the controller.
- `tls_hello_events` / `tls_hello_rate`: rate-limited truncated ClientHello
  handshake samples from standalone `netra_tlsfp` (≤256 bytes, ≤1/2s per
  destination tuple via `bpf_skb_load_bytes`). Own verifier budget —
  works even where `netra_l7_*` is rejected (kernels before 5.17). Handshake metadata only — not
  application records. See [`tls-fingerprints.md`](tls-fingerprints.md).

## Cleartext HTTP/1

For an egress TCP skb that begins with a recognized HTTP/1 request method, Netra scans the same skb for a `Host:` header and records only:

- method (`GET`, `POST`, `PUT`, `HEAD`, `PATCH`, `DELETE`, `OPTIONS`);
- Host header;
- cgroup/workload identity;
- request counter and last-seen time.

Request paths, query strings, cookies, authorization headers, bodies and response content are not exported. HTTPS, HTTP/2 and HTTP/3 are not decoded as HTTP metadata.

A response whose first bytes are `HTTP/1.0 ` or `HTTP/1.1 ` plus a three-digit code is counted in `http_status_stats`, keyed by cgroup and status. That is a fixed offset, not a header scan and not stream reassembly. A status line split across packets is invisible. The reason phrase is not stored. Counted packets are IPv4 with no options, or IPv6 with next-header TCP, and a TCP header of 20–40 bytes. Each payload offset is a constant so the verifier finishes with the rest of the object.

Map: `http_host_stats` for method and Host. Map: `http_status_stats` for the status code. The status counter is `netra_http_status_ingress` / `netra_http_status_egress`, not the SNI/Host scan programs, so kernels that reject the scan programs (before 5.17) still load it.
Linux smoke: `sudo ./scripts/ci-http-status-smoke.sh` (GitHub job
`http-status-smoke`).

## Connection attempts

The existing cgroup socket hooks now maintain exact destination-attempt counters keyed by cgroup, address family, protocol, remote IP and remote port. TCP rows represent `connect()` attempts; UDP rows represent `sendmsg()` operations captured by the hook.

Map: `connect_attempts`.

The controller uses TCP attempt counters with sockops active-establishment counters to produce an **estimated** connection-failure signal. Because these are cumulative kernel counters rather than a one-to-one transaction trace, the estimate is intentionally labeled heuristic. High unique endpoint fan-out is also surfaced as an investigation signal; it is not labeled as proof of scanning.

## Operator surfaces

```bash
netractl ebpf l7
netractl ebpf sni add telemetry.example.com
netractl ebpf mode enforce 15m
netractl ebpf sni del telemetry.example.com
```

Dashboard: **L7 Metadata**.

API: `GET /api/v1/ebpf/l7`.

Prometheus metrics are aggregate/low-cardinality. Hostnames and destination addresses are intentionally not emitted as metric labels.

Flow history can label a destination port with a well-known name (`mysql`, `postgres`, `redis`, `kafka`, `grpc` on 50051, `http`, `https`). That label is a port hint, not a decode of those protocols, and not a substitute for the SNI/Host parser above. gRPC on 443 stays `https`. See [`flow-log.md`](flow-log.md).

## Implementation note: why this runs in its own program

SNI/HTTP/DNS-qname parsing runs in dedicated `netra_l7_cgroup_egress`/`netra_l7_cgroup_ingress` programs (`bpf/netra_tc.c`), separate from `netra_cgroup_egress`/`netra_cgroup_ingress` (the conntrack + IP/CIDR/port/rate/NetworkPolicy-deny program). This is deliberate, not incidental: a `cgroup_skb` BPF program is force-inlined into one function frame, so the verifier must account for the union of every helper's locals against the kernel's hard 512-byte stack limit. Once conntrack and NetworkPolicy-shaped deny were added to the CT/policy program, that frame was already at its limit — folding the L7 scan buffers back into the same function is exactly what silently disconnected this feature for a time (the parser functions were still defined but never called; see `CHANGELOG.md`). Keeping L7 parsing in its own program gives it its own, independent verifier budget. If you're modifying either program, do not merge them back into one — reintroduce that same failure mode.

The two programs run independently of the CT/policy program's own verdict for the same packet (the kernel ANDs multiple `cgroup_skb` programs' verdicts at the same attach point): an SNI/DNS deny here returns a block on its own. One accepted, documented consequence: `flow_stats`/`workload_flow_stats`'s `blocked` counter only reflects IP/CIDR/port/rate/NetworkPolicy denies from the CT/policy program, not SNI/DNS denies from this one — the packet is still genuinely dropped either way; Drop Detective sees the SNI/DNS-specific block via `policy_drops`/`REASON_SNI`/`REASON_DNS` regardless.

Gated by `NETRA_L7=auto|off|required` (default `auto`), mirroring `NETRA_TCX`'s attach-with-fallback convention: on either an attach failure or a kernel verifier rejection at load time, the agent logs a warning, drops these two programs, and continues without L7 observability rather than failing startup. A verifier rejection fails the *whole* BPF collection load (all programs in the ELF, not just the rejected one), so the agent detects that it was specifically these two programs that failed and reloads without them, rather than crash-looping the whole agent over an observability-only feature. Set `NETRA_L7=required` to fail startup instead if L7 observability must not silently degrade.

### How the parsers stay inside the verifier's limits

The DNS question, SNI and Host parsers (`bpf/netra_l7.h`) do not walk packet memory. The program copies up to 640 payload bytes with `bpf_skb_load_bytes` into a `struct netra_l7_work` in the per-CPU `pkt_scratch` map, then walks that copy with `bpf_loop`:

- SNI and Host search positions 0–511 (SNI from 43), one `bpf_loop` callback per position; a matching name or value is copied by a nested `bpf_loop`, one byte per step. DNS decodes the question one byte per step.
- The verifier checks each callback once, with an unknown index, instead of every iteration with a known one. Parser state (output length, label bytes left, the result) lives in the map, so the verifier reads it as unknown too and never multiplies its states by it.
- Indexes are masked or bounds-checked against the 640-byte buffer, so every read is in bounds whatever the packet holds; bytes past those actually copied are rejected by the parser logic, never relied on.

The earlier open-coded loops failed on Linux 6.8 and 7.0 with "the sequence of 8193 jumps is too complex": the loop index addressed memory, so the verifier tracked one state per iteration and its queue of unexplored branches passed the fixed 8192 limit. Once that was lifted, the unrolled DNS QNAME decoder alone exceeded the 1,000,000-instruction budget. With `bpf_loop`, `netra_l7_cgroup_egress` verifies in about 95,000 instructions and `netra_l7_cgroup_ingress` in about 37,000 (Linux 7.0, clang 18; clang 21 also loads).

Limits and requirements:

- `bpf_loop` needs Linux 5.17 or newer. On older kernels these two programs are rejected and `NETRA_L7=auto` drops them as before; the HTTP status counters and the rest of the datapath are unaffected.
- The parsers see the first 640 payload bytes of the one skb, including any part outside its linear area. An SNI extension or `Host:` header that starts at byte 512 or later is not found, as before.
- The HTTP method is read from the same copy, as are SNI and Host: an egress request's bytes are usually outside the skb's linear area.
- A DNS response is matched to its query by the receiving socket's cgroup (`bpf_skb_cgroup_id`). On ingress the program runs in softirq, where `bpf_get_current_cgroup_id()` names whatever task was interrupted, and responses never matched.
- Computing the payload offset subtracts two packet pointers, which the verifier allows only to a privileged loader (`CAP_PERFMON` or `CAP_SYS_ADMIN`); the agent runs privileged.

Verify a change on a Linux host before shipping it: compile `bpf/netra_tc.c` with the `Dockerfile.agent` flags and `bpftool prog loadall` the object into a throwaway bpffs directory. Clang versions emit different bounds checks (clang 18 adds a loop index before re-checking it, and folds compare pairs), so test the compiler the image uses.
