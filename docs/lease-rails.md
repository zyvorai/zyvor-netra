# Lease safety rails

Operator-configured limits checked when a deny lease is created (a denyset `add` or `extend`). **Every rail is off unless you set it**, so a controller with no `NETRA_LEASE_*` variables behaves exactly as before.

| Variable | Rail | Code |
|---|---|---|
| `NETRA_LEASE_MAX_CONCURRENT` | most denyset leases active at once (all owners, after the apply) | `lease_rail_max_concurrent` |
| `NETRA_LEASE_MAX_DURATION` | longest lease, e.g. `2h`. Also bounds the enforce-mode lease of `PUT /api/v1/ebpf/mode` | `lease_rail_max_duration` |
| `NETRA_LEASE_MAX_BREADTH_V4` | total IPv4 addresses across active CIDR leases (a `/24` is 256) | `lease_rail_max_breadth` |
| `NETRA_LEASE_MAX_BREADTH_V6` | total IPv6 `/64` networks across active CIDR leases (a `/48` is 65536) | `lease_rail_max_breadth` |
| `NETRA_LEASE_BREAK_GLASS_REQUIRED=true` | a catch-all (`/0`) rule, or a rule the lockout check says reaches a protected destination, needs a break-glass confirm | `lease_rail_catch_all`, `lease_rail_protected` |
| `NETRA_LEASE_ACTOR_RATE=10/1m` | lease creations plus extensions per actor per window | `lease_rail_actor_rate` |

A malformed value is reported on `GET /api/v1/ebpf/deny-leases/rails` (`configError`) and in the controller log, and the rails stay off rather than guess.

## Break-glass

With the break-glass rail on, a request that would add a catch-all or protected-destination rule passes only with `breakGlass` (a justification of 8 to 200 printable characters). It is recorded on the lease timeline and as the audit event `ebpf.denyset.breakglass` with the actor, rail codes and reason. Break-glass waives only those two rails. Count, duration, breadth and rate always hold. An invalid justification is refused with `lease_rail_break_glass_invalid`.

## Dry run

`netractl denyset plan FILE` (and `POST /api/v1/ebpf/denysets/plan`, MCP `netra_denyset_plan`) reports `rails.trips` (what would refuse the apply), `breakGlassRequired` and `applicable`. A dry run never consumes the rate budget. A plan blocked by a hard rail gets no apply receipt.

## Decisions are visible

Every refusal returns a stable `code` (HTTP 422, or 429 for the rate rail) and `trips`, is written to the lease timeline as a `reject` event, audited as `ebpf.denyset.rail.reject`, and counted in `netra_lease_rail_trips_total{code}`. A rate-limited apply counts toward the actor's budget even when another rail refuses it.

`GET /api/v1/ebpf/deny-leases/rails`, `netractl denyset rails`, MCP `netra_deny_lease_rails` and the **Deny Leases** console page show the configuration and current usage. Rails cannot be changed through the API; they are environment configuration.
