# Research: round 4 (flow comparison and incident hand-off)

Searches run on 2026-11-24. Vendor pages are marketing: treated as claims, not facts. Items marked (unverified) could not be confirmed from a primary source.

| Source | What it does | Used in Netra |
|---|---|---|
| ntop.org threat detection page (fetched) | Baseline anomaly alerts: new host, unusual destinations, unexpected data volumes, off-hours activity, new internal connections | Dependency drift (new and vanished edges), volume shift. No off-hours model (no time-of-day baseline yet) |
| Kentik synthetic monitoring article (fetched) | Destination inventory built from real traffic, path and routing change correlation, impact scoping; active probe metrics need probes | Not copied: probe metrics cannot be measured passively and Netra has no BGP feed. The "inventory follows real traffic" idea is the basis of edge-based drift |
| Cilium policy audit rollout guide (fetched), CNCF/Isovalent policy testing posts | Audit mode shows would-be drops as AUDIT; enforce when no AUDIT events remain for a business cycle | Already covered by deny preview (live and flow history) and leased deny; the clean-window idea informs "gone quiet" reporting. No new feature |
| Akvorado / ElastiFlow search results | Top talkers, ASN breakdowns; no first-seen report found in either (unverified for newer releases) | Flow summary export (earlier round) already covers the IPFIX-name side; no ASN data in Netra |
| Datadog Cloud Network Monitoring search | DNS health views (volume, latency, failure rate), thresholds; no dependency-change detection found (unverified) | Netra's DNS detect and DNS response diagnostics already cover these |
| Kentik 2026 platform updates search | Autonomous investigation across synthetic, flow and BGP; vendor-reported | Incident bundle and report remain the offline hand-off; the API now serves verify and report |

Ranked ideas not built: off-hours or time-of-day baselines (needs per-hour history), ASN or provider concentration (needs a geo or ASN database), a Hubble-style AUDIT stream for leased denies.
