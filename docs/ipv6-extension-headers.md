# IPv6 extension headers and fragmentation

Netra v0.16 closes the main IPv6 parsing gap in the standalone datapath. The cgroup, TCX/TC and XDP paths no longer assume that TCP or UDP begins immediately after the fixed 40-byte IPv6 header.

## Supported walk

The datapath performs a verifier-bounded walk of at most six extension headers and understands:

- Hop-by-Hop Options (`0`)
- Routing (`43`)
- Fragment (`44`)
- Authentication Header / AH (`51`)
- Destination Options (`60`)

ESP (`50`) is intentionally opaque. `No Next Header` (`59`) is treated as having no L4 payload.

## Fragment semantics

Netra is conservative around fragments:

- An atomic fragment (`offset=0`, `M=0`) is parsed like an ordinary packet.
- A first fragment (`offset=0`, `M=1`) may expose TCP/UDP ports and metadata when the complete upper-layer header is present.
- A non-first fragment never supplies trusted ports or L7 metadata. Netra preserves the Fragment header's immediate `Next Header` value and continues source/destination address, CIDR and flow accounting.
- If an extension header is malformed/truncated, or the chain exceeds six headers, Netra suppresses L4/L7 parsing rather than guessing. Address/CIDR decisions remain available.

This prevents a non-first fragment from being accidentally interpreted as a TCP/UDP header while avoiding a blanket drop of fragmented IPv6 traffic.

## Enforcement behavior

| Packet form | IPv6 exact/CIDR | TCP/UDP port | DNS/SNI/HTTP metadata |
|---|---:|---:|---:|
| No extension header | yes | yes | yes, where otherwise supported |
| Supported extension chain | yes | yes | yes, where otherwise supported |
| Atomic fragment | yes | yes | yes, where otherwise supported |
| First fragment with complete L4 header | yes | yes | best effort |
| Non-first fragment | yes | no | no |
| ESP | yes | no | no |
| Malformed/depth-limited chain | yes | no | no |

In `scopeMode=selected`, the existing Netra rule remains unchanged: interface-level TCX/XDP enforcement is observe-only because those hooks do not have trusted workload identity.

## Why six headers?

The limit is intentional. It keeps the eBPF control flow small and predictable across Netra's Linux 5.8+ baseline while covering realistic extension chains. Exceeding the limit does not cause Netra to invent a transport offset; L4/L7 parsing is simply disabled for that packet.

## Validation

`bpf/tests/ipv6_walk_test.c` exercises direct L4, chained options, AH, atomic/first/non-first fragments, ESP/No-Next-Header, malformed lengths and the depth bound using the exact header-walking helper compiled into the eBPF datapath.

See `docs/ipv6-diagnostics.md` for the counters this walk feeds into `ipv6_ext_stats` and the resulting `GET /api/v1/ebpf/ipv6` diagnostics surface.
