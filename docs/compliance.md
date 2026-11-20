# Compliance packs

CIS-inspired **network hardening** pack built from existing
[`sysctl-audit`](sysctl-audit.md) findings. Review-only — Netra never writes
sysctls. Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

Pack `network-hardening` maps controls such as `rp_filter`, SYN cookies,
ICMP redirects, and source routing to **pass / warn / fail** with per-node
evidence from the latest sysctl-audit snapshot.

```text
GET /api/v1/compliance
netractl compliance
```

**UX:** Surfaces → Compliance.

Not a certified CIS assessor.

See [competitive-quantum.md](competitive-quantum.md), [buyers guide](sales/buyers-guide.md).
