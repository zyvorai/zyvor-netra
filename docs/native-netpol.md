# Optional native NetworkPolicy deny maps

Netra v0.19 adds an **optional**, fail-open-by-default deny dataplane shaped like FluxVM pod policy maps — without requiring Cilium.

## Enable

The enforcement toggle is writable via `PUT /api/v1/ebpf/netpol/config` (`{"enabled": true}`), `netractl ebpf netpol enable|disable`, the `netra_ebpf_netpol_config_set` MCP tool, or the Firewall dashboard page's NETPOL card.

`netPolDenies` itself (the actual per-cgroup peer-deny entries below) has no write path yet on any surface — only the controller and agent read/apply it today. Authoring these entries directly is a planned follow-up; for now they can only be observed once populated by another mechanism, e.g. directly editing the persisted state file:

```json
{
  "netPolEnabled": true,
  "netPolDenies": [
    {
      "cgroupId": 123456789,
      "peerIpv4": "10.0.0.5",
      "port": 5432,
      "protocol": "TCP",
      "direction": "egress"
    }
  ]
}
```

Maps:

- `netpol_enabled` — array[0] = 0/1
- `netpol_deny4` — cgroup + peer + port + protocol + direction

When disabled (default), the BPF helper returns allow immediately.

## Model

- Deny-list only (matches Netra’s emergency posture).
- Port `0` means any port for that peer/protocol/direction.
- Direction `both` expands to ingress+egress entries.
- Identity key is the Linux cgroup ID already used for workload attribution.

## Not in this release

- Full Kubernetes NetworkPolicy CRD controller
- IPv6 peer map (v1 or v2)
- Maglev / Service VIP rewrite

Insights CNP drafts remain the review-only path toward CiliumNetworkPolicy.

## v2: allow-list / default-deny (per-workload)

A second, independent engine sits alongside the v1 deny-list above:
selector-targeted allow/deny rules, plus a default-deny posture per
workload. It's off by default (`netPolV2Enabled: false`) and does not
touch `netpol_enabled`/`netpol_deny4` — the two engines run side by side in
the kernel and can be enabled independently.

### Enable and author rules

- `PUT /api/v1/ebpf/netpol/v2/config` (`{"enabled": true}`), `netractl ebpf
  netpol v2 enable|disable`, `netra_ebpf_netpol_v2_config_set`, or the
  Firewall page's NETPOL V2 card.
- `POST /api/v1/ebpf/netpol/rules` adds one rule, `DELETE
  /api/v1/ebpf/netpol/rules/{id}` removes it, `GET /api/v1/ebpf/rules`
  (or `netPolRules` on `GET /api/v1/ebpf/config`) lists them. A rule is
  `{selector, peerIpv4, port, protocol, direction, action}` where `selector`
  is the same `EBPFWorkloadScope` shape used by `/api/v1/ebpf/scope`
  (namespace/pod/workloadKind/workloadName/labels), resolved to cgroup IDs
  agent-side each sync via `workload.Resolve` — the same mechanism
  workload-scoped enforcement already uses. `action` is `allow` or `deny`.
  Exact peer IPv4, or port-only (empty `peerIpv4` + exact `port`, meaning
  "any peer") — a rule needs at least one exact discriminator, enforced at
  `ebpfNetPolRuleAdd`; a request with neither is rejected with 400.
  CIDR-shaped peers and IPv6 are still explicit follow-ups.

  **Port-only allow-exceptions mirror the v1 flat engine's `allowed_ports`,
  not a new mechanism.** `netpol_v2_lookup4` does a three-step fallback on
  a miss: exact peer + exact port, then exact peer + any-port (`port=0`,
  pre-existing), then — new — any-peer (`peer=0`) + exact port. `peer=0` is
  a safe wildcard sentinel since it's never a real address on this path.
  There is deliberately no fourth "any-peer + any-port" step: such a rule
  has no real discriminator and can't exist (rejected at the API layer, so
  no such row is ever written to `netpol_rules4`).

  **Live-deployed and confirmed to load and attach with zero verifier
  rejections (0.27.51)**, and the write path was confirmed correct via a
  direct `bpftool map dump` of `netpol_rules4`. Live traffic admission
  itself couldn't be cleanly proven against a real cluster — the only
  available in-pod HTTPS test client (a `kubectl debug` ephemeral
  container) runs in a cgroup outside the target pod's resolved workload
  set, so the rule correctly never applied to it, not a sign anything was
  broken (see CHANGELOG.md's 0.27.51 entry).

  **A real kernel-execution test of this fallback ordering was attempted
  (0.27.52) and hit a genuine `BPF_PROG_TEST_RUN` constraint, not a bug**:
  `netpol_v2_lookup4` keys every lookup on `bpf_get_current_cgroup_id()`,
  which reads the cgroup associated with the packet's owning *socket* —
  for a `cgroup_skb` program driven by `BPF_PROG_TEST_RUN`'s synthetic
  packets (no real socket behind them), that helper returns 0 throughout,
  so no rule can ever match regardless of what's seeded. Confirmed via
  diagnostics on a real GitHub Actions run before concluding this (the
  Go-side map-key encoding itself was verified byte-for-byte correct).
  `cilium/ebpf`'s `RunOptions` has no field to inject cgroup context, so
  there's no userspace-side fix — see the 0.27.53 CHANGELOG entry.
  `bpf/integration/netpol_portonly_test.go` (`TestNetPolRuleKeyEncoding`)
  instead regression-guards the map-key byte encoding directly (no kernel
  invocation) — a real, still-valuable guard for the exact class of bug
  building this surfaced: `internal/agent.applyNetPolV2` stored the port
  field in host-native byte order instead of the packet's wire order,
  silently making every NetPol v2 rule with a *specific* non-palindromic
  port (not just port-only ones) a dead entry that could never match real
  traffic — see the 0.27.52 CHANGELOG entry for the full explanation. Live
  traffic remains the only way to prove `netpol_v2_lookup4`'s full runtime
  behavior end-to-end for the cgroup-hook path.

  **No UID/process-name allow-exceptions — deliberately deferred, different
  hook family, not just unfinished work.** The flat global engine's
  `allowed_uids`/`allowed_comms` exceptions are checked in `socket4`/`socket6`
  (`cgroup/connect4|connect6|sendmsg4|sendmsg6`, `bpf_sock_addr` hooks) at
  socket-creation time — the only point `bpf_get_current_uid_gid()`/
  `bpf_get_current_comm()` are valid, which is also why the project caches
  identity into `socket_owner` at connect time instead of re-deriving it
  later. `netpol_rules4` is instead looked up from `cgroup_skb/egress|ingress`
  on an already-built `__sk_buff`, where ingress traffic in particular has no
  reliable process-identity context. Adding UID/comm selectors to `NetPolRule`
  therefore isn't a field addition to the existing map/lookup; it would need
  a second, parallel per-workload table consulted from the socket hooks
  instead, plus its own API/CLI/MCP surface and evaluation-order slot
  alongside the existing flat allow/deny checks. Port-only allow-exceptions
  (peer-agnostic — `Port`/`Protocol` already exist on `NetPolRule`, a
  wildcard `peerIpv4` would suffice) don't have this hook-family mismatch and
  remain a smaller, separate candidate if picked up later.
- CLI: `netractl ebpf netpol rule add --peer IP --action allow|deny
  [--namespace NS] [--pod POD] [--kind KIND] [--workload NAME]
  [--label k=v] [--port N] [--protocol P] [--direction D]`, `netractl ebpf
  netpol rule del ID`.
- MCP: `netra_ebpf_netpol_rule_add`, `netra_ebpf_netpol_rule_delete`.

### Evaluation order (cgroup hook only)

Applies only to the `cgroup_skb` hook, since only it has `cgroup_id`; the
TC/XDP early-drop paths are unaffected and keep enforcing the flat
deny-lists exactly as before. For each non-established packet:

1. **Explicit v2 rule match** (`netpol_rules4`) — checked *first*. An
   `allow` match passes the packet immediately, **overriding every
   deny-list below it, including the flat emergency deny-list**
   (`BlockedIPv4`/CIDRs/etc.). A `deny` match blocks immediately with
   reason `netpol-rule` (numeric `10`). This is a deliberate design choice:
   an operator can carve out a narrow allow for a specific workload/peer
   even while the cluster-wide emergency deny-list is active. It is the
   behavior most likely to surprise someone reading only the flat
   deny-list — the Firewall UI warns inline when adding an allow rule that
   would override a live flat-deny entry for the same peer/port.
2. If no v2 rule matched: the flat deny-lists (`decide4`/`decide6`) run
   exactly as today.
3. Then the legacy v1 `netpol_denies4` (unchanged).
4. Finally, **default-deny posture** (`netpol_default4`) — if this
   workload's cgroup has an active default-deny entry, the packet is
   blocked with reason `netpol-default-deny` (numeric `11`); otherwise it
   passes. **Absence of an entry means fail-open**, mirroring real
   Kubernetes NetworkPolicy semantics (a pod is only ever default-deny once
   something explicitly selects it).

### Activating default-deny

Turning on default-deny for a workload selector is the highest
blast-radius mutation in the firewall feature — it can cut off all
unlisted traffic for every matched workload — so it goes through a
**mandatory plan → confirm** step, unconditionally (unlike the general
CiliumNetworkPolicy apply flow, where preflight is optional):

1. `POST /api/v1/ebpf/netpol/default-deny/plan` with
   `{selector, enabled: true}` resolves the selector against the live
   cluster (`s.kube.ListWorkloads`), counts matched workloads and how many
   already have a covering `allow` rule, and returns
   `{risk, matchedWorkloads, workloadsWithAllowRule, receipt}`. Zero
   matched workloads is a hard error. Zero of them having *any* covering
   allow rule is risk `critical` and is refused outright (409) unless the
   request is repeated with `?allowNoRules=true` — activating default-deny
   with no allow rules at all is a certain, immediate outage for that
   workload, not just a risk to warn about. Otherwise risk is `medium`.
   Deactivating (`enabled: false`) is always risk `low` and never blocked —
   turning default-deny off is the fail-open direction.
2. `PUT /api/v1/ebpf/netpol/default-deny` with the **exact same request
   body bytes**, plus header `X-Netra-Plan-Token: <receipt>` (and
   `X-Netra-Confirm-Risk: <risk>` when risk is `medium`/`high`/`critical`),
   activates or deactivates it. The token is single-use, short-lived, and
   hash-bound to the request body — any client doing this two-step hand-off
   (CLI, MCP, the Firewall UI) must send byte-identical bodies to both
   calls.
   - Optional `lease` (e.g. `"5m"`), bounded to 1m–60m, defaults to 5
     minutes — deliberately much shorter than the general enforce-mode
     lease (15m/24h default/cap), reflecting the higher per-target blast
     radius. The lease self-reverts; there is no "make it permanent" option.
3. CLI: `netractl ebpf netpol default-deny plan [selector flags]
   [--disable] [--allow-no-rules]` then `netractl ebpf netpol default-deny
   set --token TOKEN [--confirm-risk RISK] [selector flags] [--disable]
   [--lease DURATION]`. MCP: `netra_ebpf_netpol_default_deny_plan` /
   `netra_ebpf_netpol_default_deny_set`.

### One-shot quarantine

`netractl ebpf netpol quarantine [--namespace NS] [--pod POD] [--kind KIND]
[--workload NAME] [--label k=v] [--allow-peer IP[:PORT[/PROTO]]]...
[--lease DURATION] [--confirm-risk RISK] [--allow-no-rules]` is a
**client-side convenience**, not a new server capability: it composes the
three calls above (`PUT /netpol/v2/config` to enable v2 if needed, one
`POST /netpol/rules` per `--allow-peer` to seed allow rules for the
selector, then the full plan → confirm-risk → apply default-deny sequence)
into one command, for the real incident where "run five commands correctly
in order" is worse than "run one command that already knows the order."
It introduces **no new server-side logic and bypasses none of the existing
safety machinery** — the zero-covering-allow-rule `critical`-risk refusal,
the single-use receipt token, and the `X-Netra-Confirm-Risk` requirement
all still apply exactly as if the steps were run by hand.

`--allow-peer` requires an exact IPv4 (matching `NetPolRule.PeerIPv4`'s
existing exact-peer-only scope — see above); there is no DNS-name allow
rule in this engine, so quarantining a workload that still needs to resolve
names requires naming the cluster DNS service's IP explicitly, e.g.
`--allow-peer 10.96.0.10:53/UDP`. Netra does not guess this — an emergency
containment command that silently assumes the wrong DNS server IP is worse
than one that requires the operator to name it.

If the allow-peer rules are added but the subsequent plan/apply step then
fails or is refused (e.g. risk is `critical` and `--confirm-risk` wasn't
given), the rules are **not rolled back** — they are a strict safety
improvement on their own (an allow-exception before default-deny is even
active is inert) and are left in place so a retried quarantine, or an
operator finishing the job by hand with `netpol default-deny set`, doesn't
have to re-add them.

### Fail-open on restart

Exactly like the general enforce `Mode` today, no default-deny-enabled
workload survives a controller restart: `NetPolDefaultDenies` is cleared
on load, same as `Mode` resets to `observe`. A security-boundary-crossing
event (a controller restart) must never silently resume a
traffic-cutting posture — reactivating after a restart requires a fresh
plan → confirm, exactly as if activating for the first time.

### Propagation ordering

The agent's `applyNetPolV2` writes/refreshes every `netpol_rules4` entry
for a workload *before* flipping its `netpol_default4` entry to active, and
flips that entry back off *before* pruning rules on deactivation. Default-
deny-before-rules-complete is the one race window in this whole feature
that fails **closed** (an outage) rather than open, so it gets this
explicit ordering guarantee rather than relying on eventual convergence
like the rest of the full-rebuild-per-sync appliers.

## Drop attribution

NetPol-emulation denies (`netpol_denies4` hits) report their own reason code (`netpol-deny`, numeric `9`) in Drop Detective (`GET /api/v1/ebpf/diagnose`) and in `FastPathEvent.Reason`/`netra_audit`-style event streams — distinct from a manually staged CIDR deny (`cidr-deny`, numeric `2`), even though both ultimately match on peer address/port. This lets an operator tell "blocked by your NetworkPolicy emulation" apart from "blocked by an ad hoc CIDR rule" when reading drop findings.
