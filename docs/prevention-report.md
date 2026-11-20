# Prevention coverage report

Threat-prevention-style **coverage** of Netra controls — intel hits, lease
state, deny census, detector findings, AI/DoH/DoT/JA3 — not signature-IPS
efficacy percentages. Parent: [`p0-p5-surfaces.md`](p0-p5-surfaces.md).

## How it works

Builds a point-in-time snapshot answering: *are the controls we claim
actually wired and producing signal?*

Typical sections include:

- Enforce lease present / mode  
- Deny / rate / Shield census  
- Threat-intel feed loaded + recent hits  
- Detector enablement (scan, DNS, …)  
- AI destinations, encrypted DNS, JA3 unique counts  
- Aggregate **`coverageScore`** for the Report / Surfaces boards  

```text
GET /api/v1/report/prevention
netractl report prevention
```

**UX:** Surfaces → Prevention report; Report page.

See [competitive-quantum.md](competitive-quantum.md), [threat-intel.md](threat-intel.md),
[buyers guide](sales/buyers-guide.md).
