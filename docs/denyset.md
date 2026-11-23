# Declarative leased deny (`netra-denyset/1`)

A file of deny rules that is planned, diffed and applied as one unit, with every rule bounded by a lease. It is the declarative form of `netractl ebpf cidr|deny|port`, with the guards the policy plan/apply flow already has.

Boundaries, in one place:

- A denyset **cannot create a permanent rule**. `lease:` is mandatory (1m to 24h) and every rule gets one. The controller removes the rule when its lease ends.
- A denyset **only ever deletes leases it created**. Each lease carries the denyset name as its owner label. A rule that exists without a lease (added by hand, by a feed, by another path) is shown as `skip` and never taken over or removed. Another denyset's rules are never touched.
- Apply goes through the **plan token** (single use, 5 minutes, bound to the plan hash) and **`X-Netra-Confirm-Risk`**. It never changes observe/enforce. Enforce stays leased and fails open.
- Apply is refused when the plan hash no longer matches (the file or the leases changed), or when a [lease safety rail](lease-rails.md) trips.

## File format

```
netra-denyset/1
name: incident-4711          # ownership label: lowercase letters, digits, '-'
lease: 30m                   # default lease for every rule below (1m..24h)

deny cidr 203.0.113.0/24 egress
deny ip   198.51.100.7   both    lease=10m     # per-rule lease override
deny port tcp 445 ingress
```

- The first non-comment line must be `netra-denyset/1`. `name:` and `lease:` are required, once each.
- Rules: `deny cidr CIDR DIR`, `deny ip ADDR DIR` (stored as `/32` or `/128`), `deny port tcp|udp|any PORT DIR`. `DIR` is `egress`, `ingress` or `both` and is required (no silent default).
- `#` starts a comment. Unknown directives, unknown options, duplicate rules and duplicate `name:`/`lease:` are errors.
- Limits: 64 KiB per file, 512 bytes per line, 500 rules, no control characters, UTF-8 only. At most 50 errors are reported, each with its line number.
- A file with no `deny` lines is valid: planning it removes every lease the denyset owns.
- Not supported in `/1`: dns, sni, process, uid and rate rules (they have no CIDR/port lease path yet).

## Plan

```bash
netractl denyset validate incident.denyset          # local, no API
netractl denyset plan incident.denyset [--break-glass "why"] [--json]
```

`POST /api/v1/ebpf/denysets/plan` with `{"file": "...", "breakGlass": "..."}`. The plan lists each item as `add`, `extend` (lease duration changed), `remove`, `unchanged` or `skip`, and for every add/extend runs the [deny preview](deny-preview.md) (observed hits) and the self-lockout check. It also dry-runs the rails and reports which would trip. Plan changes nothing; viewers may plan.

`planHash` covers the name and every item's action, rule and lease. It does not depend on time, line numbers or comments, so the same file against the same leases always hashes the same. `risk` is `low` (nothing to add/extend), `high`, or `critical` when a rule's lockout risk is `likely`.

## Apply

```bash
netractl denyset apply incident.denyset --plan-hash <hash> --confirm-risk high [--break-glass "why"]
```

`POST /api/v1/ebpf/denysets/apply` with `{"file", "planHash", "breakGlass"}`, headers `X-Netra-Plan-Token` and (for high/critical) `X-Netra-Confirm-Risk`. The CLI re-plans to obtain the token and refuses unless the hash equals `--plan-hash`.

| Status | `code` | Meaning |
|---|---|---|
| 400 | `plan_hash_required` | no `planHash` |
| 409 | `plan_hash_mismatch` | file or leases changed; plan again (`currentPlanHash` returned) |
| 428 / 412 | `plan_token_required` / `plan_token_invalid` | missing, expired, used or other-plan token |
| 409 | `risk_confirm_required` | repeat with `X-Netra-Confirm-Risk: <risk>` |
| 409 | `state_changed` | rules or leases moved between plan and apply |
| 422 / 429 | `lease_rail_*` | a rail refused it ([rails](lease-rails.md)) |
| 422 | `denyset_invalid` | validation errors with `errors: [{line, message}]` |

Re-applying an unchanged file is a no-op (`noop: true`). To keep a lease alive, change `lease:` to a longer value; an `extend` re-leases from now.

## Lease views and timeline

Read-only, never changes a rule:

- `GET /api/v1/ebpf/deny-leases[?owner=&within=15m&expiring=true]`, `netractl denyset leases [--expiring]`, MCP `netra_deny_leases`, console **Deny Leases**: active leases with time remaining and an expiring-soon filter.
- `GET /api/v1/ebpf/deny-leases/history[?owner=&limit=&since=]`, `netractl denyset history`, MCP `netra_deny_lease_history`: create, extend, expire, revoke and rail rejections with the actor and rail decisions (including audited break-glass). The last 1000 events, persisted with controller state.
- A lease whose rule was deleted or re-created outside the denyset is dropped (event `revoke`, actor `system`) and the rule is left alone.

Metrics: `netra_deny_leases_active`, `netra_deny_leases_expiring_soon` (within 15m), `netra_deny_lease_events_total{action}`, `netra_denyset_plans_total`, `netra_denyset_applies_total`, `netra_denyset_rejects_total`, `netra_lease_rail_trips_total{code}`. No metric-alert rule ships for leases (the metric alert engine evaluates agent-collected series, not controller state); alert from Prometheus, for example:

```yaml
- alert: NetraDenyLeaseExpiringSoon
  expr: netra_deny_leases_expiring_soon > 0
  for: 1m
```

## MCP

Read-only (always available): `netra_denyset_plan` (sends `X-Netra-No-Receipt`, so a read-only session never obtains an apply token), `netra_deny_leases`, `netra_deny_lease_history`, `netra_deny_lease_rails`. Behind `NETRA_MCP_ALLOW_MUTATIONS`: `netra_denyset_plan_receipt` and `netra_denyset_apply`.

## What this does not do

- It writes through the existing store (`BlockedCIDRs`/`BlockedPorts` and the rule index), the same path as `netractl ebpf cidr|port`. It does not touch BPF maps or the agent; agents pick the rules up from the controller config as for any other rule.
- Leases are enforced by the controller. A controller that is down does not remove expired rules until it runs again, and a restarted controller still demotes enforce to observe, so rules in the config only act while an enforce lease is active.
- A manual `ebpf cidr add` of the exact same rule while a lease exists is a no-op; the lease still owns and later removes it. Delete and re-add by hand and the lease is dropped instead.
- The lockout check is the controller's own view (see [deny-preview.md](deny-preview.md)).
