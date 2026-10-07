# Threat-intel live pipeline

Operator-loaded IP/CIDR/DNS/SNI lists that match live agent metadata and
can optionally apply as lease-bounded denies. Metadata only — no payloads.

```text
PUT    /api/v1/intel/feed          # replace active feed (same body as preview)
GET    /api/v1/intel/feed          # status + entries
DELETE /api/v1/intel/feed          # clear
GET    /api/v1/intel/hits          # observe-only match against agents
POST   /api/v1/intel/apply         # leased deny import (confirm required)
POST   /api/v1/intel/preview       # parse only; still applies nothing
```

```bash
netractl intel feed FILE
netractl intel hits
netractl intel apply [--matched-only]
```

## Apply gates

`POST /api/v1/intel/apply` requires:

1. `mode=enforce` with an **active lease**
2. header `X-Netra-Confirm-Risk: high`
3. optional `?matchedOnly=true` to import only entries that currently hit

Fails open when the lease expires (same as every other deny).

**UX:** Surfaces → Threat intel feed / DNS intel hits. Parent catalog:
[`p0-p5-surfaces.md`](p0-p5-surfaces.md).

See also: [competitive-quantum.md](competitive-quantum.md), [firewall.md](firewall.md),
[buyers guide](sales/buyers-guide.md).

## Feed history, expiry and refresh

Feed imports now support canonical indicators, optional TTL and revision guards, retained history and rollback, optional persistent journaling and leader-owned HTTPS refresh. See [Security intelligence and review](security-review.md) for environment variables, API routes and failure/expiry behavior. Feed updates never apply deny entries.
