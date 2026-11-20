# ICMP error diagnostics

When a connection stalls, a router or destination may report a packet-too-big,
unreachable, time-exceeded, or parameter error. Netra now records these IPv4 and
IPv6 ICMP error headers at its TC ingress/egress hooks and turns the observations
into next investigation steps.

Open **Health → ICMP diagnostics**, or use **Explain** with a node-wide scope:

```bash
netractl explain --node worker-1
netractl explain --node worker-1 --format json
netractl ebpf stats > agents.json
netractl explain --input agents.json --node worker-1
```

The existing `/api/v1/agents` response adds `icmpErrors` entries with interface
index, current interface name when available, address family, type, code, direction, hook (`tc`), cumulative packet
observations, last advertised MTU when present, and kernel-monotonic last-seen
nanoseconds. No new endpoint, privilege, enforcement action, or application
payload collection is introduced.

| Signal | Header | Next check |
| --- | --- | --- |
| MTU / packet too big | IPv4 type 3/code 4; IPv6 type 2/code 0 | Interface/tunnel MTUs and delivery of ICMP errors to the sender |
| Destination unreachable | Other IPv4 type 3; IPv6 type 1 | Exact code, destination listener, routes, firewall rejects |
| Time exceeded | IPv4 type 11; IPv6 type 3 | Hop limits/routing loops or fragment reassembly timeout, according to code |
| Parameter problem | IPv4 type 12; IPv6 type 4 | IP headers and tunnel configuration |

## Evidence boundaries

- Only the fixed eight-byte ICMP error header is parsed. Quoted original packets
  are not retained or attributed to a workload, destination, port, or connection.
  Echo requests/replies are excluded. IPv4/IPv6 fragments and IPv6 jumbograms are
  conservatively excluded; IPv6 extension parsing retains the existing bound.
- These are **TC observations**, not counts of unique network failures. A packet
  can cross several observed interfaces. Cgroup and XDP hooks do not populate
  this map. An interface index can be reused after an interface is deleted.
- Counters are cumulative since map creation or LRU eviction, not rates. Fresh
  agent reports can contain older observations. Last advertised MTU and last-seen
  time are best-effort concurrent snapshots. They need not describe the same
  packet. The MTU is an unvalidated peer claim, not a verified path MTU; no packet
  checksum verification or active probe is added here.
- Node-wide Explain includes these signals; namespace, pod, PID, exact-container,
  Docker, destination, and DNS scopes exclude them to avoid false attribution.
- Health excludes stale reports, reports older than two minutes, and reports over
  one minute in the future. Explain uses its existing configurable age bound.
  Missing data can mean an older agent/object, no attached TC hooks, no matching
  packets, non-linear/truncated headers, or map eviction. It does not prove health.
- The additive `icmp_errors` LRU map has at most 4096 entries: 8-byte keys and
  24-byte values. Collection work and report rows are also bounded. Existing map
  layouts and Netra's enforcement verdicts remain unchanged. Only Netra's own pin
  directory is used. Older BPF objects without the map continue reporting their
  other evidence; deploy the new agent and object together to enable this feature.

## Validation

The shared host parser test checks truncated headers, echo exclusion, every
IPv4/IPv6 type-and-code pair, and network-byte-order MTUs. Go tests check the map
ABI decoder, old-object compatibility, report JSON, scope isolation, freshness,
and diagnostic classification. Web tests cover the same scope/freshness boundary,
empty states, escaping, and the 50-row presentation bound.

CI compiles the full BPF object and runs the parser test. Before production rollout,
load the object on a supported Linux kernel and exercise ICMPv4 fragmentation-needed
and ICMPv6 packet-too-big traffic through attached TC interfaces. Confirm reported
interface/direction/type/code and advertised MTU, then confirm echo traffic does not
increment the map and workload-scoped Explain does not show these node signals.
Compilation and host tests alone do not establish kernel verifier acceptance.
