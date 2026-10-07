# Netra product brochure (source)

The brochure is built from this directory, so it can be regenerated when the product changes.

```sh
python3 docs/sales/brochure/build.py            # writes Zyvor-Netra-Product-Brochure.pdf here
python3 docs/sales/brochure/build.py --check    # also fails if any page's content overflows
```

Standard library only. The PDF is rendered by the installed Google Chrome in headless mode (`CHROME=/path`
selects another Chromium-based browser). Then copy the PDF to `../Zyvor-Netra-Product-Brochure.pdf` and
`../../../website/static/sales/`.

| File | What |
|---|---|
| `pages_*.html` | the pages, one `<section class="page">` each (header, footer and page numbers are added by `build.py`) |
| `style.css` | the Zyvor look (orange `#ff5a15`, ink, warm paper), US letter |
| `diagrams.py`, `svg.py` | the ten diagrams, drawn in code (`{{dia:name}}` in a page inserts one) |
| `build.py` | assembles the pages and prints the PDF |

Screenshots are the lab captures in `docs/ux/` (single physical copy). They are captioned "illustrative"; the
diagrams are conceptual. Fonts are the system Helvetica Neue stack, embedded as subsets by Chrome.

## Where each claim comes from

Re-check these when the product changes; a number in the brochure that is not in this table should not be there.

| Claim | Source |
|---|---|
| 28 dashboard pages | `Page` type in `web/src/components/Nav.tsx` |
| 8 eBPF objects, hooks, defaults, kernel needs (ring buffer 5.8+, batch reads 5.6+, TCX 6.6+, BTF only for drop attribution) | `bpf/netra_*.c`, `docs/standalone-ebpf.md`, `docs/edge-tcp-intel.md`, `docs/tcp-events.md`, `docs/drop-info.md`, `docs/l7-sampling.md`, `docs/tls-plaintext.md` |
| 189 MCP tools (129 read, 60 mutating, off by default) | the real server's `tools/list`; `scripts/ci-mcp-live.sh` |
| Reason numbers differ by kernel (`NETFILTER_DROP` 8 on 6.8, 12 on 6.17); attribution card examples | `docs/drop-info.md` |
| Alert poller 30 s; triggers (softnet drops, drop-rate spike > 3x average and >= 50, critical from 200, critical Congestion Map); 5 min dedup | `internal/alert/poller.go`, `docs/drop-diagnostics.md` |
| Auto-capture opt-in; 10 min per-node cooldown; 5 concurrent; 60 s and 1000 pps defaults; store 50 files / 1 GB | `internal/alert/autocapture.go`, `internal/capture/artifact.go`, `docs/capture.md` |
| Manual capture up to 5 min; filter required; 16 MB ring buffer; frames up to 9000 bytes; both backends produce the same frames | `docs/capture.md`, `bpf/netra_capture.c`, `internal/capture/capture.go` |
| Context bundle contents; comm-only process list; what is never collected | `docs/tutorials/drop-incident-context.md`, `docs/kernel-network-diagnostics.md` |
| PCAP download needs the operator role; roles; static key is admin | `docs/auth-oidc-rbac.md` |
| Lease 1 min to 24 h, default 15 min; fail-open causes; `NETRA_FAILSAFE_AFTER` 60 s | `internal/api/server.go` (`ebpfMode`), `internal/agent/agent.go`, `website/docs/security.md` |
| Deny preview (applies nothing); blast radius 1 to 6 hops, default 3, observed traffic only | `docs/deny-preview.md`, `docs/blast-radius.md` |
| Single-use preflight receipts apply to CiliumNetworkPolicy and NetPol default-deny, not to an exact-IP deny | `internal/api/server.go`, `docs/gitops.md` |
| Sampling: first 128 bytes, allowlisted output, roles, kernel-enforced process allowlist, host-PID view | `docs/l7-sampling.md`, `docs/tls-plaintext.md` |
| Measured costs (~100 ns / ~540 ns per drop; 29 to 65 ns; ~1.0 to 1.4 us per TLS probe; agent 194% to ~23%) | `docs/drop-info.md`, `docs/l7-sampling.md`, `docs/tls-plaintext.md`, `docs/agent-map-reads.md` |
| OIDC, metrics token, mutual TLS (optional, shared certificate) | `docs/auth-oidc-rbac.md`, `docs/agent-mtls.md` |
| Sinks and formats | `docs/otlp-push.md`, `docs/loki-push.md`, `docs/siem-export.md`, `docs/snowflake-export.md`, `docs/alerting.md` |
| Testing: enforcement, capture, upgrade and rollback, HA, browser, nightly, kernels 6.8 and 6.17 | `docs/ci.md`, `scripts/ci-*.sh` |
| License wording | `LICENSE`, README "License" |
