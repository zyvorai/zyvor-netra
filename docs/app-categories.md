# App / category catalog

Heuristic CDN / SaaS / cloud / social / finance labels from SNI, HTTP Host,
and DNS names. **Not DPI** and not a 10k-app signature product.
Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

`internal/appcat` matches hostname suffixes; **longest suffix wins**.
Results feed Surfaces, destination-risk, category-deny drafts, and
prevention coverage.

```text
GET /api/v1/ebpf/app-categories
netractl ebpf app-categories
```

MCP tool: `netra_ebpf_app_categories`. Resource: `netra://ebpf/app-categories`.

**UX:** Surfaces → App categories.

See [competitive-quantum.md](competitive-quantum.md), [buyers guide](sales/buyers-guide.md).
