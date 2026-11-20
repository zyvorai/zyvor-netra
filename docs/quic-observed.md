# QUIC-observed traffic counter

**This is not SNI extraction.** Netra's TLS SNI parsing (`tls_sni_stats`)
works because a TLS `ClientHello` is sent in cleartext. QUIC does not have
that property: RFC 9001 mandatorily applies *header protection* to every
Initial packet — the packet type that would carry a `ClientHello` — and
removing that protection requires deriving per-connection keys via
HKDF-SHA256 and decrypting with AES-128 or ChaCha20. None of those
primitives exist as BPF helpers, and implementing them in BPF bytecode
(even if the verifier allowed the complexity) would mean Netra doing real
cryptography in the kernel to read plaintext that was deliberately encrypted
against on-path observers — a different category of feature than anything
else in this project. So QUIC SNI extraction was never attempted.

What `quic_observed` tracks instead: for every UDP/443 packet, whether its
first payload byte matches RFC 9000's long-header wire form — top bit set
(`0x80`) and the "fixed" bit set (`0x40`). Long-header packets are QUIC's
Initial/Handshake/Retry/0-RTT types, sent only during connection setup;
the bulk of a QUIC connection's traffic is short-header packets (top bit
clear), which this counter does not match. That makes `quic_observed` a
**handshake-attempt indicator**, not a QUIC traffic-volume counter — a
workload can send many QUIC packets to a remote endpoint while
`longHeaderPackets` stays small if only the first handshake produced
long-header packets and everything since has been short-header.

A UDP/443 destination is also not proof of QUIC. Any UDP traffic to port
443 increments the same key's `packets` counter regardless of what's
actually inside it; `longHeaderPackets` is the heuristic-matched subset.
Treat a nonzero `longHeaderPackets` as "this looks like it might be a QUIC
handshake," not a certainty — the byte pattern is not unique to QUIC in the
general case, only checked against the RFC 9000 form.

## Attach point and cgroup attribution

Populated from the same `cgroup_skb/egress`/`cgroup_skb/ingress` call site
as `udp_flow_health` (see [UDP flow health beyond DNS](udp-flow-health.md)
for why that's the correct attach point for real cgroup attribution, rather
than the `tc/egress`/`tc/ingress` programs). No new hook, no
`decide4`/`decide6` change.

## API and UI

`GET /api/v1/ebpf/health` adds `quic: []` and two summary counters,
`quicObservedFlows`/`quicLongHeaderPackets`. The Health page's
**QUIC OBSERVED** tile and **QUIC-OBSERVED FLOWS** table render them.

## Evidence boundaries

- Only unblocked UDP/443 packets are counted, matching `udp_flow_health`'s
  blocked-packet exclusion.
- Keyed by cgroup + remote IP + remote port (always 443 today), not a full
  4-tuple flow — this is a per-destination observation counter, not a
  connection tracker.
- The additive `quic_observed` LRU map holds at most 65536 entries: 32-byte
  keys, 24-byte values. Existing map layouts and enforcement verdicts are
  unchanged.

## Validation

`bpf/tests/abi_layout_test.c` guards the `quic_observed_key`/
`quic_observed_value` struct sizes. `internal/agent`'s
`TestDecodeQUICObservedABI`/`TestDecodeQUICObservedABIv6` check the
byte-offset decode with literal bytes (this caught a real offset bug during
development — the key's 3-byte pad after `family` shifts `remote_addr` to
offset 12, not 9); `TestQUICObservedUnavailableWhenMapMissing` and
`TestEnrichQUICObservedSkipsZeroCgroup` cover the map-absent and
zero-cgroup enrichment paths. CI compiles the full BPF object. Before
production rollout, load the object on a supported Linux kernel, generate
real QUIC traffic (e.g. an HTTP/3 client) to a workload, and confirm
`quic_observed` entries show a nonzero `longHeaderPackets` during the
handshake and a growing `packets` count afterward — compilation and host
tests alone do not establish kernel verifier acceptance.
