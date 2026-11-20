# How the agent reads its BPF maps

The agent reports flow, TCP-health, UDP and QUIC statistics every 3 seconds. They live in
five LRU hash maps of up to 131 072 entries each (`workload_flow_stats`, `flow_stats`,
`tcp_health`, `udp_flow_health`, `quic_observed`), plus a `conntrack` table that is only
counted.

## What it used to cost

Each report walked every entry of every table with `Map.Iterate` (two syscalls per entry:
get-next-key, then lookup), decoded and formatted **every** entry (two IP strings and a
struct), sorted **all** of them, and kept the first 1 000. The work was proportional to the
size of the table; the report was not.

Measured on a live node (Linux 6.8, busy shared host): the agent averaged **194% of a core**
and 313 MiB RSS. Tracing 40 seconds of its `bpf()` calls (862 000 of them) attributed 30% each
to `udp_flow_health`, `workload_flow_stats` and `flow_stats`, 2.4% to `conntrack`, and 7% to the
two newer sensors' tables. On a synthetic 100 000-entry pair of flow maps one `readStats` took
**275 ms and allocated 253 MB** (522 000 allocations) per call, so most of the CPU was the
garbage collector cleaning up strings that were about to be thrown away.

## What it does now

Three separate ideas, only two of which are needed at today's table sizes:

1. **Batched reads** (`internal/mapscan`). `BPF_MAP_LOOKUP_BATCH` returns about a thousand
   entries per syscall, into one reused buffer, with views handed to the caller so nothing is
   allocated per entry. 60 000 entries take 59 syscalls instead of 120 000. A bucket larger
   than the batch (`ENOSPC`) grows the buffer; a kernel or map type without batch support falls
   back to `Iterate`.
2. **Rank raw, decode few** (`mapscan.TopN`). One pass over the raw bytes keeps a bounded
   min-heap of the best N by a score function, copying only entries that displace the current
   worst. Only those N are decoded, formatted and enriched. Ties are broken by key, so reading
   an unchanged table twice returns identical rows (the old sort was unstable there).
3. **A CPU budget** that stretches the interval when a scan is slow. *Not built.* At 100 000
   entries the whole `readStats` is 19 ms every 3 s (about 0.6% of a core), so a governor would
   be machinery without a problem to solve. The instrumentation below is what would tell us
   otherwise.

| `readStats`, 100 000 entries in each of two maps | before | after |
|---|---|---|
| time | 275 ms | 18.7 ms |
| allocated per call | 253 MB | 1.6 MB |
| allocations per call | 521 874 | 7 268 |

## The report is unchanged

`internal/agent/legacy_readers_test.go` keeps the original loops verbatim. Tests build real
BPF maps of the production shapes, fill them with random entries (overflowing the 1 000 cap
several times), run both, and require the outputs to be **deep-equal** for `readStats`,
`readTCPHealth`, `readUDPFlowHealth` and `readQUICObserved`. They also cover ties, tables below
the cap, a missing map (an error, or optional for `flow_stats`, exactly as before) and a map
whose layout differs from what the agent decodes (refused, not misread). They run against a
real kernel in the privileged CI job and fail the job if they skip.

## Seeing what a read costs

Every report carries `mapScans`: for each map read, the entries visited, the `bpf()` syscalls it
took, whether it was batched, and its wall time (`GET /api/v1/agents`). The controller exports
the worst node per map as `netra_agent_map_scan_millis_max{map}`,
`netra_agent_map_scan_entries_max{map}` and `netra_agent_map_scan_unbatched_nodes{map}`; a read
over one second is logged as a warning. The original problem was found only by attaching
`strace` to a production process.

## Limits

- **Not atomic.** Like `Iterate`, an entry that changes during a read may be missed or seen
  twice. The maps hold cumulative counters, so the next report corrects it.
- **Other readers still iterate.** Maps that are small (per-cgroup, per-interface, per-rule) keep
  `Iterate`; only the five large tables and `conntrack` moved. `mapScans` shows if another grows.
- **The tables are large because the keys are high-cardinality** (the source port is part of the
  flow key), so a busy node fills them. Aggregating in the kernel would shrink them; that changes
  what the datapath records and is a separate decision.
- Batch lookup needs Linux 5.6 or later; earlier kernels use the fallback and `unbatched_nodes`
  says so.
