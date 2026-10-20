# AI review (netra)

_Generated 2026-10-20 by claude-opus-5-5 from a snapshot of tracked sources; verify before acting._

# Code review: Netra (`zyvorai/zyvor-netra`)

## Summary

Netra is a standalone eBPF network observability and "leased" emergency-enforcement product for Linux and Kubernetes. It has these parts:
- a Go controller (`netrad`), a node agent (`netra-agent`), a CLI (`netractl`) and an MCP server (`netra-mcp`);
- a React dashboard (`web/`), a Docusaurus site (`website/`), and an optional Python LangGraph companion (`python/`);
- a Helm chart and plain manifests.

Cilium and Hubble integration is optional. The repository also carries a large amount of sales and marketing collateral.

## Bugs and correctness risks

- **`internal/leaseclock/leaseclock.go`**
  - `rem := int64(exp.Sub(now).Seconds())` truncates toward zero.
  - A lease with 0.1–0.99 s left therefore reports `Expired: true, Active: false` while it is still enforcing.
  - Compare durations (`exp.After(now)`) for the state, and round or ceil only for display.
- **`cmd/netractl/config_test.go`: global state leak.**
  - `TestTLSInsecureLoopbackDefault` assigns the package-global `base` and never restores it.
  - `useTestServer` in `testutil_test.go` does restore it, so this test is the outlier.
  - Later tests in the package can end up pointing at `127.0.0.1:30870`, depending on order.
- **Bash scripts with `set -u` and empty arrays.**
  - Affected: `scripts/deploy-container.sh` (`"${ARGS[@]}"`) and the `ci-*-unit.sh` scripts (`"${RACE_FLAG[@]}"` when `RACE=0`).
  - These abort with "unbound variable" on bash < 4.4.
  - That includes macOS's default bash 3.2, which the other build scripts explicitly target ("Google Chrome and macOS `sips`").
  - Use the `${ARR[@]+"${ARR[@]}"}` form.
- **`scripts/deploy-container.sh` argument contract looks inconsistent.**
  - It documents `user@host` and passes `--k3s` to `deploy-remote.sh`.
  - `QUICKSTART.md` documents `deploy-remote.sh HOST USER --k8s`.
  - It then uses `ARGS[0]` as the ssh target.
  - One of these is wrong. `deploy-remote.sh` is not shown, so I can't say which.
- **`deploy/rbac-cilium.yaml` may overwrite the base role.**
  - It defines `ClusterRole`/`ClusterRoleBinding` named `netra` with only `ciliumnetworkpolicies` rules.
  - If `deploy/rbac.yaml` (not shown) also uses the name `netra` for the Pods/Services read role, applying the Cilium file replaces it.
  - That would silently drop workload attribution. Worth verifying; use a distinct name such as `netra-cilium`.
- **`internal/agent/exehash_gate_linux.go`**
  - It deletes every `exehash_pids` entry, then re-scans `/proc` and re-inserts. This leaves:
    - a window in which the gate is empty;
    - partial state if a `Put` fails midway;
    - no coverage for processes that exec a blocked binary between reconciles.
  - The comment acknowledges the TOCTOU, but the delete-then-fill order makes it worse than necessary. Compute the new set first, then diff it against the map.
- **`internal/afcapture/ratelimit.go`**
  - The comment says "sliding window", but the code is a fixed 1-second window keyed on `Unix()`.
  - It allows up to 2× `maxPPS` across a window boundary. Fix the doc or the implementation.
- **Byte-slicing can split multi-byte UTF-8 characters.**
  - `internal/notify/format.go` `SMSBody` does `s[:max-3]`, and `Title` emits `·`.
  - `internal/kmsg/kmsg.go` does `line[:180]`.
  - Either can produce invalid UTF-8 on the wire.
- **`internal/tlsfp/frame.go`**
  - The inner `if len(frame) >= 14` is always true, so the "raw IP fallback" only runs when the bytes at offset 12–13 are not an IP ethertype.
  - A raw IPv4 packet whose source-IP bytes 12–13 happen to equal `0x0800` or `0x86dd` is misparsed.
  - `afcapture/classify.go` ignores 802.1Q tags while `tlsfp` handles them, which is inconsistent.
- **`internal/api/p4_surface.go` `fleetTenants`**
  - Every GET fans out synchronously to all peers with a 10 s timeout, passing a `nil` client (default unknown).
  - Repeated dashboard polling multiplies outbound load. Consider caching.
- **Hard-coded versions that will drift:**
  - `const version = "0.32.0"` in `cmd/netra-mcp/main.go`;
  - Chart `version`/`appVersion`.
  - There is no evidence of a single source of truth or a CI check.

## Security concerns

- **`web/src/auth.ts` ships demo credentials in the client bundle.**
  - It contains `admin` / `Admin@321` and maps them to the bearer `Admin@321`.
  - The comment "keep in sync with default lab/deploy NETRA_API_KEY" implies some deploy paths use this well-known static admin key.
  - Remove it, or gate it behind a dev build flag.
- **Bearer token storage.** The token is kept in `localStorage` (`netra-token`, see `auth.test.ts`). The static key is admin (per the brochure claims table), so any XSS yields full admin.
- **Agent skips TLS verification by default.**
  - `deploy/README.md` documents that the agent sets `NETRA_TLS_INSECURE=true` for the generated self-signed cert.
  - The privileged agent therefore does not verify the controller, and the agent key and desired config are MITM-able.
  - Prefer mounting the generated CA into the agent.
- **Fleet peer API keys.**
  - Keys sit in plaintext env vars (`NETRA_FLEET_PEERS`).
  - Nothing in the shown code enforces `https://` peer URLs; the tests use `http://`. Uncertain whether `fleet.Aggregate` rejects http.
- **`deploy/netra-auth.example.yaml`** uses literal `replace-me` keys. If someone applies it as-is, the auth keys are trivially guessable. Add a guard, or rename it so it can't be picked up by globs.
- **`hack/smoke.sh`** falls back to unauthenticated calls to `/api/v1/*`. That is fine for a smoke test, but it implies unauthenticated mode is common.
- **CI supply chain.**
  - Actions are pinned to major tags (`actions/checkout@v7`, `deploy-pages@v5`), not SHAs.
  - A self-hosted runner pool is in use (fork PRs are correctly excluded).
- **Pre-release and heavy dependencies.** `go.mod` depends on a pre-release `github.com/cilium/cilium v1.21.0-pre.3` and a netlink pseudo-version, and pulls in AWS, Azure and Snowflake SDK trees. That is a large attack surface for a privileged product.

## Test and CI gaps

- **Tests that don't test what they claim:**
  - `TestInstallSelfCLI` (`cmd/netractl/install_cli_test.go`) re-implements the copy instead of calling `installSelfCLI`.
  - `TestNoActionWithoutEnforceLease` (`internal/automitigate`) asserts nothing meaningful on the enforce path; it only checks `Enabled`.
  - `TestSimulatePolicyRejectsInvalidJSON` accepts either 400 or 502.
  - `web/src/pages/Features.test.ts` and `Surfaces.test.ts` only assert route registration.
- **Weak lint coverage.**
  - `.golangci.yml` runs only four linters with `only-new-issues`, so the legacy backlog is invisible.
  - There is no `errcheck` or `gosec`, which matters for a privileged eBPF agent.
- **No SPDX header check**, even though `CONTRIBUTING.md` and `AGENTS.md` require the header. Files missing it include:
  - `internal/handoff/handoff.go`, `internal/procmeta/boot.go`;
  - `internal/agent/procmeta_other.go`, `capgate_other.go`, `sysres_other.go`;
  - many `*_test.go` files;
  - most `web/src` components;
  - all Helm templates.
- **No CI tests for the boundary cases above:** lease sub-second expiry, the fixed-window rate limiter at a boundary, and UTF-8 truncation.
- **Documentation and marketing builds are not reproducible in CI.**
  - Card, brochure and pricing builds require macOS `sips` and Chrome.
  - Two scripts write the same JPEGs with different scale factors and heights: `docs/ux/build-readme-cards.sh` uses `scale=2`, measured height; `docs/social/readme/build.sh` uses `scale=1`, fixed heights.
- **Website deploy runs without a separate check.** `pages.yml` builds and deploys with no link check, even though the docs contain broken-looking Pages URLs (see below).
- **CodeQL `autobuild` for Go may not build** the cgo or eBPF parts. I can't verify this without seeing CodeQL's output.

## Documentation gaps

- **Inconsistent Pages URLs.**
  - `website/README.md` says the site lives at `zyvorai.github.io/zyvor-netra/`.
  - `SECURITY.md` (the only pointer to the threat model), `docs/sales/README.md` and `website/README.md` ("served at `/netra/sales/...`") use `/netra/...`.
  - `helm/netra/Chart.yaml` `icon` points at `zyvorai/netra` on raw.githubusercontent.
  - These are likely broken links.
- **Mismatched MCP tool counts.** `README.md` says 190, while `docs/ux/readme-capabilities.html` says "MCP: 189 stdio tools".
- **Stale README content.**
  - "What's new" covers 0.28.2→0.30.0 while the stated latest release is 0.32.0.
  - The README hero is `docs/social/netra-hero-dark.jpg`, but `docs/social/README.md` describes `netra-share-card.png` as the hero and doesn't list the hero-dark build at all.
- **Contradictory card build instructions.**
  - `docs/social/README.md` says the README cards come from `docs/social/readme/*.html`.
  - The HTML files in `docs/ux/` say "Build: ./docs/ux/build-readme-cards.sh".
  - Pick one source.
- **Pages trigger paths disagree.** `website/README.md` lists `website/`, `docs/ux/`, `docs/social/`, while `pages.yml` triggers on all of `docs/**`, `CHANGELOG.md`, `server.json`, and others.
- **Incomplete CI job list in `AGENT
