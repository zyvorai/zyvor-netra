# Research: support and flight-recorder bundles

Short survey behind `docs/incident-bundle.md`. Claims from memory that were not re-checked against current docs are marked [U].

## What the field does

| Tool | Shape | Redaction | Takeaway for Netra |
|---|---|---|---|
| Kubernetes `kubectl cluster-info dump`, OpenShift `must-gather` | Directory or tarball of API objects and pod logs gathered on demand | Secrets are not dumped by default [U]; logs and ConfigMaps are not scrubbed and may hold credentials | Collect on demand into one archive; do not rely on the operator to scrub afterwards |
| `sosreport` / `sos` (Linux) | Plugin-based tarball of config and logs | Optional obfuscation of hostnames, IPs, MACs, usernames with a mapping file kept by the collector [U] | Stable pseudonyms within a report are enough to reason about topology; keep the mapping out of the artifact |
| Cilium `sysdump` | Tarball of cluster state, agent logs, BPF map and endpoint dumps | `--hubble-flows`, secrets excluded by default [U] | Include BPF attachment and datapath state, not only logs |
| Datadog Agent flare | Zip of config, logs, status | Scrubber with a list of key patterns (api keys, passwords, tokens, URL credentials) applied to every file [U] | A single scrubber for every string beats per-field ad hoc handling |
| Cisco `show tech-support` | Concatenated command output | None built in; operators scrub by hand [U] | A deny-list after the fact is what fails in practice |
| AWS Support bundles / `ecs-logs-collector`, `eks-log-collector` | Script that gathers logs and config into a tarball | Collects instance metadata; no IP or secret masking [U] | Say plainly what is in it before the user attaches it |
| Linux perf / BPF flight recorders (`perf record` ring, `bpftrace` ring, Tetragon and Pixie ring buffers) | Always-on bounded ring, dumped when something happens | Process arguments and payload are the usual leak [U] | Reuse the rings that already exist; bound everything; keep argv out |

## Design decisions drawn from it

1. **View, not collector.** The recorder is a read over the stores Netra already keeps, so enabling it changes nothing about what is observed or retained.
2. **Allow-list by type.** Fields are named in Go structs; verify decodes with unknown fields refused, so a new store field cannot reach a bundle by accident.
3. **One scrubber, applied to every string**, plus a verify that re-runs the same rules, so a hand-edited or third-party bundle is checked the same way.
4. **Masking is keyed and optional.** Keyed HMAC pseudonyms are not reversible by enumerating IPv4 space; prefix-preserving masking (Crypto-PAn, Fan et al. 2004 [U]) keeps subnet structure for readers who need it, at the cost of leaking which addresses share a prefix.
5. **Hard bounds and visible truncation**, so a bundle cannot grow without limit and a cut is never mistaken for quiet.
6. **Tamper evidence, not authenticity.** A hash chain and a tar manifest catch edits and corruption; signing needs a key the controller does not hold today, so it is left out and stated.
7. **Deterministic output** (sorted keys, fixed list order) so a before/after diff shows changes in the network, not in the serializer.

## Known limits

- The metric store keeps per-second data for about an hour and rolled-up tiers beyond that, so a 24 h window carries coarse points (at most 120 per series).
- Agent counters for DNS, TLS and HTTP metadata are cumulative since agent start; a bundle cannot window them.
- A restart of an agent or the controller clears in-memory history; it appears as a gap.
