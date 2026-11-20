# SYN-drop mode

Adding an exact-IP deny rule normally drops *every* packet matching that
address and direction — including packets belonging to a connection that
was already open before the rule existed, or one Netra's own conntrack
simply never saw the handshake for (agent restart, LRU eviction, or the
connection predates the agent attaching). SYN-drop mode is a narrower,
per-rule alternative: **only drop a genuinely new TCP connection attempt**
(a SYN packet with ACK clear) for that address+direction; let every other
TCP packet through.

This is additive, not a replacement — flag only the specific exact-IP
entries where you want the gentler behavior. Most deny rules don't need
it.

## Scope

- **Exact-IP and CIDR deny are both covered.** CIDR-matched deny
  (`REASON_CIDR`) is flagged via a second LPM trie, `syndrop_cidr_v4`/
  `syndrop_cidr_v6`, keyed identically to `blocked_cidr_v4`/`blocked_cidr_v6`
  (direction packed into the same byte, prefixlen covering direction +
  address) — since the deny LPM trie's own lookup returns only a boolean
  match with no rule identity, the SYN-drop flag can't share that map and
  needs its own trie mirroring the same key shape. Use
  `netractl ebpf syn-drop-cidr add/del <cidr> <direction>`, the
  `POST /api/v1/ebpf/syn-drop-cidr` / `POST /api/v1/ebpf/syn-drop-cidr/delete`
  endpoints (matching the exact-IP pair's add/`…/delete` shape, not a
  `DELETE`-method route), or the Firewall page's SYN-DROP MODE card's
  second row.
- **TCP only.** UDP and other protocols have no "new connection" concept;
  a SYN-drop flag has no effect on non-TCP traffic — the deny rule behaves
  exactly as before for it.
- **Has no effect without a matching deny entry.** A SYN-drop flag for an
  address+direction that isn't also in `blockedIPv4`/`blockedIPv6`
  (egress) or `blockedIngressIPv4`/`blockedIngressIPv6` (ingress) is
  inert — it doesn't create a deny rule on its own. Add the deny entry
  first (`netractl ebpf deny add`), then flag it.
- Direction is exactly `egress` or `ingress` — never `both`, unlike the
  deny CIDR rules themselves. The underlying kernel maps
  (`syndrop_v4`/`syndrop_v6`/`syndrop_cidr_v4`/`syndrop_cidr_v6`) are all
  inherently per-direction; add two entries if you need both.

## Usage

```bash
netractl ebpf deny add 203.0.113.10 egress      # the deny rule itself
netractl ebpf syn-drop add 203.0.113.10 egress  # narrow it to new SYNs only
netractl ebpf syn-drop del 203.0.113.10 egress  # revert to full drop
```

Or via the Firewall page's SYN-DROP MODE card, or the
`netra_ebpf_syn_drop_add`/`_delete` MCP tools.

## Design: a real kernel-verifier risk, taken carefully

This is the first change in the "tons of eBPF feats" push that adds a
conditional branch directly inside `handle_v4`/`handle_v6`'s hot TC/
cgroup_skb path (byte-rate capping, by contrast, only changed a function
signature — no new branch on the common path). That hot path is not a
place this project treats added complexity casually: `docs/l7-metadata.md`
documents a real prior verifier rejection, though at a different location
(the SNI/HTTP scan loops in the separate `netra_l7_cgroup_egress/ingress`
programs, not this CT/policy program) — the lesson generalized here is
"be careful adding complexity to an already-large BPF program," not that
this exact branch was previously rejected.

Mitigations, matching the plan's own requirement:

- **New side-map, not an ABI change.** `syndrop_v4`/`syndrop_v6` are
  separate additive maps, keyed by address+direction with a plain `__u8`
  presence marker. `blocked_v4`/`blocked_v6`/`blocked_ingress_v4`/
  `blocked_ingress_v6`'s pinned value type is untouched.
- **The added logic runs only inside the already-rare `blocked==1`
  branch**, gated behind `reason==REASON_EXACT && proto==IPPROTO_TCP &&
  !syn_new` — three cheap comparisons the caller already has in registers
  — before the one extra hash lookup. The common allow path (the vast
  majority of packets) does zero extra work.
- `struct ct_state` (the existing conntrack value struct) is untouched —
  the earlier plan draft that suggested extending it with a
  handshake-established marker was dropped in favor of the side-map
  approach outlined above, since a side-map avoids resizing a pinned
  value type that upgrade-in-place agents already depend on.

**Exact-IP SYN-drop is live-verified.** It was deployed and confirmed
end-to-end against a real Kubernetes API server and kernel (see project
history around 0.27.34): the map loads under `/sys/fs/bpf/netra/`, a
flagged exact-IP deny rule drops new connection attempts while an
already-open connection through the same address keeps flowing, and
reverting the flag restores full-drop behavior.

**The CIDR extension (`syndrop_cidr_v4`/`syndrop_cidr_v6`) reuses an
already-proven LPM_TRIE map type** (`blocked_cidr_v4`/`blocked_cidr_v6`
already load and enforce correctly on real kernels) and adds one more
`||` disjunct to the existing bounded `blocked==1` conditional — no new
branch shape, no ABI change. Live-deployed and confirmed to load and
attach with zero verifier rejections (0.27.51); the full-block control
and new-connection-refused behavior were also confirmed live, but the
specific "a pre-existing connection keeps flowing" distinction couldn't
be cleanly proven against a live, shared cluster — every raw-socket test
client tried had its connection die within 15-30s regardless of whether
any rule was active, a test-fixture problem, not a firewall effect (see
CHANGELOG.md's 0.27.51 entry).

**That exact distinction is now covered deterministically instead**:
`bpf/integration/syndrop_cidr_test.go` (`TestSynDropCIDR`,
`TestSynDropExactIP`) loads the real compiled BPF program and runs it
against synthetic packets via the kernel's `BPF_PROG_TEST_RUN`, in CI, on
every push — proving `!syn_new` is a pure per-packet TCP-flag check (SYN
set, ACK clear), independent of conntrack state, so a non-SYN packet for
a flagged address/direction is let through with zero dependency on a real
connection's lifecycle. See `bpf/integration/helpers.go`'s package doc
comment for how this harness works and why it exists.
