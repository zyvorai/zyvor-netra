# Shadow SaaS (CASB-lite)

Ranks observed SNI / HTTP Host / DNS names against a **sanctioned host
suffix** allow-list. No content inspection — metadata only.
Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

1. Operator sets `NETRA_SANCTIONED_HOSTS` (comma-separated suffixes) or Helm
   `sanctionedHosts`.
2. Controller joins live agent L7/DNS metadata against:
   - the sanctioned list
   - a built-in “known SaaS / AI” catalog (same family as app/AI categories)
3. Each finding gets a status:
   - **`shadow`** — known SaaS/AI host **not** on the allow-list  
   - **`unknown`** — uncatalogued host (visibility gap)  
   Sanctioned hosts are counted in rollups but omitted from the findings board.

```bash
export NETRA_SANCTIONED_HOSTS='office.com,okta.com,github.com,slack.com'
# Helm: sanctionedHosts: "office.com,okta.com,..."
```

```text
GET /api/v1/insights/shadow-saas
netractl insights shadow-saas
```

**UX:** Surfaces → Shadow SaaS.

## Containment (separate step)

Optional leased SNI deny after review — see [`threat-intel.md`](threat-intel.md)
and [`ai-destinations.md`](ai-destinations.md). Netra does not auto-block
shadow findings.

Pairs with [`policy-packs.md`](policy-packs.md) (sanctioned allow drafts).

See [competitive-sse.md](competitive-sse.md), [buyers guide](sales/buyers-guide.md).
