# Firewall dashboard page

The dashboard's **Firewall** nav page (formerly labeled "eBPF") is the single
place to see, edit, and audit every eBPF-enforced rule, including the
per-workload NetPol v2 allow-list/default-deny engine (see
`docs/native-netpol.md` for the full kernel-side model).

## CLI map inventory

Before or after editing rules in the UI, operators can dump the same desired
state from the CLI:

```bash
netractl ebpf maps          # human board
netractl ebpf maps --json
```

This is the controller inventory under `/sys/fs/bpf/netra` (not a raw
`bpftool` dump). Full reference: [`ebpf-maps.md`](ebpf-maps.md).

## Unified rules table

The table at the top of the page flattens every rule type into one view:
exact IPv4/IPv6 deny (egress or ingress), exact IPv4/IPv6 allow-exception,
CIDR deny, CIDR allow-exception, port, port allow-exception, UID,
UID allow-exception, process, process allow-exception, capability-gated
socket deny (see [Capability-gated socket deny](capability-gated-deny.md)),
DNS, SNI, rate limit (independent PPS and/or BPS caps on the same rule —
see [Byte-rate (BPS) cap](#byte-rate-bps-cap)), plus a synthetic row each
for the DDoS shield (when its mode isn't `off`) and NetPol (when enabled).

The TYPE column is color-coded by what the rule actually does: red for a
deny rule (the bare types above, plus NetPol/NetPol V2), green for an
`allow-*` exception, amber for `rate`/`shield` (a throttle rather than a
hard allow/deny) — see `ruleTypeClass()` in `web/src/lib/ebpfRules.ts`.

Every real rule (the 18 flat types — not the Shield/NetPol synthetic rows)
has a **stable ID** (e.g. `cidr-3`) assigned the first time it's created,
tracked in a server-side index kept separate from `EBPFFastPathConfig`
itself — the wire shape every existing agent/CLI/MCP caller already depends
on is unchanged. The ID survives edits, so:

- **Edit** opens an inline form (fields specific to that rule's type) and
  sends `PATCH /api/v1/ebpf/rules/{id}` — this changes the rule's value in
  place under the same ID and records a revision, rather than the
  delete-old/add-new dance the per-type cards below the table still use.
  The exact-IP, CIDR, port, UID, and process allow-exception types
  (`allow4`/`allow6`/`allow-cidr`/`allow-port`/`allow-uid`/`allow-process`)
  and the ingress-deny types (`ip4-in`/`ip6-in`) are add/delete-only —
  there is no in-place edit for them; the rules table's Edit action is not
  offered for those rows.
- **History** shows every edit to that rule (before/after, actor, time) via
  `GET /api/v1/ebpf/rules/{id}/history`. Creating or deleting a rule remains
  visible via the Audit page instead — only edits get their own revision
  history, since that's the case a real before/after diff is useful for.
- **Undo this edit** on a history entry rolls back to the value the rule had
  *before* that edit (`POST /api/v1/ebpf/rules/{id}/rollback/{revision}`),
  itself recorded as a new revision rather than rewriting history.
- **Delete** on the unified table calls `DELETE /api/v1/ebpf/rules/{id}`, a
  thin ID-based wrapper over the same store mutation the per-type card's
  delete button already used — there's no second deletion code path.

Rules created before this ID system shipped are backfilled on the
controller's next restart, attributed to `system:migration` rather than a
fabricated actor/timestamp.

## Capacity indicators

Every rule-type card shows a live `count / limit` line. The limits are the
real, hardcoded BPF map sizes compiled into `bpf/netra_tc.c` (4096 entries
for most rule types, 8192 for CIDR's LPM tries, 65536 for the legacy NetPol
deny map, 65536 for NetPol v2 allow/deny rules, 16384 for NetPol v2
default-deny postures, 4096 for connection-rate-limit rules) — see
`ebpfRuleLimits` in `internal/api/server.go`, also returned as `limits` on
`GET /api/v1/ebpf/capabilities`. These are compile-time constants; raising
one requires a source change and a program rebuild, not a runtime setting.
The one exception is capability-gated deny's own `count/limit`, which
reflects `deniedCapabilities`' fixed 2-name vocabulary (`CAP_NET_RAW`/
`CAP_NET_ADMIN`), not a BPF map size — the actual per-PID `capgate_pids`
map (8192 entries) isn't a rule-count limit at all, since it's populated
by the agent's `/proc` scan, not by how many capability names are denied.

## Bulk deny-list import

`POST /api/v1/ebpf/deny/import` (`netractl ebpf deny import FILE`) bulk-populates
the existing exact-IP, CIDR, DNS-name, and SNI deny primitives from an
operator-supplied list — up to 1000 entries per request. It introduces **no
new validation or detection logic**: every entry is dispatched through the
exact same per-type validator (`netip.ParseAddr`, `netip.ParsePrefix`,
`normalizeDNSName`) and store `Add` function the single-rule endpoints
already use, so an imported entry behaves identically to one added by hand.
This is a bulk-apply convenience for an operator-supplied file. For a
**live** threat-intel feed (load once, match continuously, optional leased
apply), see [`threat-intel.md`](threat-intel.md).

The CLI file format is one `TYPE VALUE [DIRECTION]` entry per line
(`ip`/`cidr`/`dns`/`sni`), blank lines and `#`-prefixed comments ignored:

```
# quarantine list, incident-2026-09-13
ip 203.0.113.5 egress
cidr 198.51.100.0/24 ingress
dns malware.example.com
sni exfil.example.net
```

The response reports **per-entry** success/failure (`{results, applied,
failed}`) rather than all-or-nothing, since a real operator-supplied list
usually has a few bad lines — a malformed entry never blocks the rest of
the import from applying.

## Shield and NetPol

The SHIELD and NETPOL cards configure two engines that were already fully
enforced in the kernel datapath before this page existed, but had no way to
be turned on:

- **Shield** — a DDoS per-source-class (SYN/UDP/ICMP/other) PPS token-bucket
  limiter, independent of the enforcement lease above it. See
  `docs/tcx-and-shield.md`.
- **NetPol** — a legacy per-cgroup peer-deny engine. The card here only
  toggles enforcement and lists existing entries read-only; authoring new
  entries has no UI yet (see `docs/native-netpol.md`).

Both mutations use full-replace semantics (the whole config object is sent
on every change, not a partial patch) — the same pattern the existing
workload-scope and rate-limit controls already use.

## NetPol V2: allow-list and default-deny

The NETPOL V2 card configures the newer, independent per-workload engine
(`docs/native-netpol.md` has the full kernel-side evaluation order). It has
three parts:

- **Enable/disable** — a plain toggle (`PUT /api/v1/ebpf/netpol/v2/config`),
  independent of the legacy NETPOL card above.
- **Rules** — a form to add one allow/deny rule: a workload selector
  (namespace/pod/kind/name/label, same shape as the enforcement-scope
  form), a peer IPv4, optional port/protocol/direction, and an
  allow/deny action. Existing rules render as chips with a delete action.
  **An `allow` rule can override the flat global emergency deny-list** for
  matching traffic — this is called out directly in the form, not left as
  a surprise discovered later in Drop Detective.
- **Default-deny activation** — a workload selector plus an optional lease,
  with a mandatory **Plan** step before **Activate** is enabled: planning
  shows how many workloads match and how many of them already have a
  covering allow rule. Zero coverage is refused outright by the server
  (visible in the UI as a blocking error, not just a warning) unless
  explicitly overridden. A **Deactivate** control is always available with
  no plan step, since turning default-deny off is the safe, fail-open
  direction.

Both the rule-add and default-deny forms resolve their selector against the
live cluster server-side — they require a working Kubernetes client
(`s.kube`) and will show a plain error if run against a controller instance
without one (e.g. a local, non-cluster test run).

## SYN-drop mode

The SYN-DROP MODE card flags an *existing* exact-IP deny entry (from the
EXACT IP card above) so only a genuinely new TCP connection attempt is
dropped for that address+direction, not every packet — see
[SYN-drop mode](syn-drop.md) for the full design, its scope (exact-IP and
TCP only, not CIDR or UDP), and the kernel-verifier risk this carries as
the first change to add a conditional branch directly in the hot
`handle_v4`/`handle_v6` packet path.

## Byte-rate (BPS) cap

The RATE CONTROL card's per-destination cap was PPS-only until this
release. `EBPFRateLimit` (the existing "rate" flat rule type — no new type,
no new endpoint, no new stable-ID namespace) gained an independent `bps`
field alongside `pps`: a destination rule can set either, both, or neither
(all-zero is refused as a no-op). `PUT`/`PATCH /api/v1/ebpf/rate[/{id}]`
accept both fields; the unified rules table's rate rows and the RATE
CONTROL card's chips show both when set (`500pps · 5000000Bps`).

This is the first Tier-3-class change in this project's "tons of eBPF
feats" push: it required changing `decide4`/`decide6`'s signature to take
a packet-length argument, rippling through all 8 existing call sites (the
two TC/cgroup_skb branches of `handle_v4`/`handle_v6`, `socket4`,
`socket6`, and the two XDP-ingress paths). Only the two `handle_v4`/
`handle_v6` call sites pass a real length — `socket4`/`socket6` and the XDP
callers already pass `apply_rate=0` (rate limiting has always been
packet-path-only), so the new length argument is inert there. New parallel
maps `rate_bps_v4`/`rate_bps_v6` (config) and `rate_byte_state_v4`/
`rate_byte_state_v6` (per-second byte counters, reusing the existing
`rate_state` struct — its `count` field holds cumulative bytes here, not a
packet count) sit alongside the existing PPS maps, never resizing them.
Byte-rate drops surface separately from packet-rate drops in
`GET /api/v1/agents`' new `byteRateDrops` (Health page's BYTE-RATE DROPS
card), since a destination's PPS and BPS caps fire independently and
conflating them would lose which one actually triggered.

## Connection-rate limit

The CONNECTION-RATE LIMIT card caps new TCP connection attempts per second
for every workload matching a selector — the same compound
namespace/pod/kind/name/labels shape NetPol v2 rules use, not a scalar key,
so it has its own dedicated add/delete endpoints
(`POST`/`DELETE /api/v1/ebpf/conn-rate-limit[/{id}]`) rather than living in
the unified rules table above. **Not part of NetPol** — it's a separate
enforcement primitive, checked on TCP `connect()` attempts only
(`cgroup/connect4`/`cgroup/connect6`); UDP `sendmsg()` is connectionless and
excluded. When more than one rule matches the same workload, the strictest
(lowest) `perSecond` applies — these are caps, not quotas that sum.

The agent resolves each rule's selector against its own cgroup→workload
table every sync (the same `workload.Match` mechanism NetPol v2 and
workload-scoped enforcement already use, so it degrades the same way
without a Kubernetes client — cgroup-only identity, no namespace/pod
labels) and writes the strictest matching `perSecond` into a per-cgroup BPF
map, `conn_rate_limits`. Drops surface in `GET /api/v1/agents`'
`connRateDrops` (Health page's CONNECTION-RATE DROPS card) and use a new
BPF reason code (`conn-rate-limit`) distinct from the existing
per-destination `rate-limit` reason.
