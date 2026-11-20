# TLS fingerprints + encrypted DNS

P1 surfaces that close the “encrypted traffic” story **without** HTTPS
break or DPI. Parent catalog: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## UX

Dedicated console page: `#page=tls-fingerprints` (`web/src/pages/TlsFingerprints.tsx`).
Surfaces still boards Encrypted → TLS / JA3 risk; L7 deep-links into Surfaces.

## JA3 / JA4 (`internal/tlsfp`)

Fingerprints are parsed from **single-skb ClientHello** bytes from two
feeds that share one userspace parser:

### 1. Datapath (always-on)

Standalone program `bpf/netra_tlsfp.c` attaches on **cgroup egress** with
its **own verifier budget**, so JA3 still works when `netra_l7_*` fails to
load.

| Piece | Role |
|---|---|
| `tls_hello_events` | Perf/ring samples of ClientHello bytes (fixed ABI; see `bpf/tests`) |
| `tls_hello_rate` | ≤1 sample / 2s / destination tuple |
| `tls_hello_scratch` | Per-CPU scratch for `bpf_skb_load_bytes` (not pinned) |

Linear `data`/`data_end` walks often miss handshake bytes on real skbs;
the program copies via `bpf_skb_load_bytes` into scratch, then emits.

Agent path:

1. Read samples from the map  
2. Parse JA3 + JA4 in userspace (`internal/tlsfp`)  
3. Include `tlsFingerprints` on each agent sync report  

Gate with `NETRA_TLSFP=auto|off|required` (Helm: agent tlsfp settings).

### 2. Capture stream

Operator or auto-capture frames still feed the same detector — useful for
forensics and for environments where the datapath program is off.

### Limits (by design)

- No TCP reassembly across skbs  
- No decryption / certificate validation story  
- Same privacy boundary as L7 SNI metadata — no payloads  

```text
GET /api/v1/ebpf/tls-fingerprints
GET /api/v1/ebpf/tls-fingerprints/risk
netractl ebpf tls-fingerprints
netractl ebpf tls-fingerprint-risk
```

**UX:** Surfaces → TLS fingerprints / JA3 risk; L7 page summaries.

### Tests / CI

| Layer | How |
|---|---|
| Unit | `./scripts/ci-tlsfp-unit.sh` (also `make test-tlsfp`) — parse, GREASE, ECH, risk, detector, API |
| P1–P5 suite | `./scripts/ci-p1-p5-unit.sh` (also `make test-p1-p5`) — all surface packages + routes |
| BPF ABI | `bpf/tests/abi_layout_test.c` (`tls_hello_event` = 276 bytes) |
| BPF load | `sudo ./scripts/ci-ebpf-tests.sh` — compile + `bpf/integration` `TestTLSFP*` |
| Live smoke | `sudo ./scripts/ci-tlsfp-smoke.sh` (GitHub job `tlsfp-smoke`): agent + **openssl** + **iperf3** → `uniqueJa3 > 0` |

```bash
./scripts/ci-tlsfp-unit.sh
./scripts/ci-p1-p5-unit.sh
# Privileged Linux:
sudo ./scripts/ci-ebpf-tests.sh
sudo ./scripts/ci-tlsfp-smoke.sh
```

## DoT / DoH (`internal/encdns`)

| Signal | Source |
|---|---|
| DoT | Destination / connect-attempt port **853** |
| DoH | Known public DoH hostnames via SNI / HTTP Host / DNS |

```text
GET /api/v1/ebpf/encrypted-dns
netractl ebpf encrypted-dns
```

**UX:** Surfaces → Encrypted DNS; L7 page.

## Related P5 boards

- ECH / missing SNI — [`p5-surfaces.md`](p5-surfaces.md)  
- JA3 risk — same fingerprint store, ranked  

See also: [l7-metadata.md](l7-metadata.md), [competitive-quantum.md](competitive-quantum.md),
[capture.md](capture.md), [buyers guide](sales/buyers-guide.md).
