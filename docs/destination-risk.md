# Destination risk scoring

Combines threat-intel hits, app/AI categories, encrypted DNS (DoH/DoT),
external exposure, and packet volume into one ranked destination list.
Observe-only. Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

For each observed destination (IP and/or hostname), the scorer accumulates
reasons such as:

- Active intel feed hit (IP/CIDR/DNS/SNI)  
- AI / MCP SaaS or sensitive app-category label  
- DoH/DoT usage toward that dest  
- External / non-cluster exposure  
- Relative packet or connection volume  

Higher score sorts first. Load an intel feed ([`threat-intel.md`](threat-intel.md))
to surface intel-hit reasons; without a feed, category/exposure/volume still
rank.

```text
GET /api/v1/insights/destination-risk
netractl insights destination-risk
```

**UX:** Surfaces → Destination risk. Pairs with [`prevention-report.md`](prevention-report.md).

See [competitive-sse.md](competitive-sse.md), [buyers guide](sales/buyers-guide.md).
