# Native investigation UX

This release connects Overview, native Connections, and observed Workloads using existing read-only APIs. Cilium and Hubble are not required for these views. Existing inventory, console, firewall, and policy tools remain accessible.

**Surfaces** (Diagnostics + Security) boards every P0–P5 observe API — JA3,
encrypted DNS, shadow SaaS, destination risk, exfil/lateral, compliance,
fleet tenants, prevention coverage, and more. See
[`p0-p5-surfaces.md`](p0-p5-surfaces.md) and the
[buyers guide](sales/buyers-guide.md). L7, Fleet, and Report deep-link into
the same boards.

## Workflow

1. Overview shows requested protection mode, independent Shield mode, reporting-agent coverage, health signals, and behavior drift. Actions open the corresponding workspace.
2. Connections filters recent agent events by exact namespace/pod/node, protocol, direction, outcome, or a case-insensitive text search. URLs preserve filters across reload and browser history; Copy view link includes no authentication token.
3. Explain connection opens a keyboard-accessible modal with source/destination, process metadata when reported, observation hook, timestamps, reported outcome, and reason. Escape closes it and restores focus. This is a per-row, client-heuristic explanation of one already-displayed event — distinct from the dashboard's separate **Explain** nav page (`docs/explain.md`), which runs the same selector-based, multi-finding diagnostic as `netractl explain` against live agent reports.
4. Open workload shows agent-reported identity, owner, node freshness/mode, and matching native events. Existing Pods/VMs inventory also links to this view.
5. Surfaces groups Encrypted / Fit / Threat / Ops / Fleet boards; each tab polls its read-only API every ~20s and lists severity-ranked rows (observe-only — no apply from this page).

Polling runs every 10 seconds, serially, with cancellation on unmount. Connections can pause polling. Failed refreshes retain the last successful snapshot with a visible warning. Tables render at most 50 event rows per page; workload cards are capped at 100 with a narrowing prompt.

## Evidence boundaries

- Agent inventory is not expected-node inventory; zero reports is unverified coverage.
- Detached programs may be optional. Program-report presence is not proof of traffic traversing every hook.
- Event buffers are sampled and bounded. The Connections page is not historical search. Queryable flow deltas (7 days, sidecar file, not a column store) are a separate API: [`flow-log.md`](flow-log.md). No fabricated time-range selector is provided on Connections.
- `observed` means Netra did not block at that hook, not that the application received traffic.
- Events contain no stable winning rule ID or historical policy generation. Explanations quote the reported reason without inferring a historical rule from current config.
- Identity comes from agent attribution, never an IP-only join. A VM launcher pod is not guest-process attribution.
- Legacy diagnostic pages keep their own filters. Shared scope applies to the new Connections and Workloads views; Overview actions explicitly open a global investigation.
- For a fused DNS → connect → netlink → policy → drops timeline with an explicit visibility boundary, use [`investigate-connection.md`](investigate-connection.md) (`POST /api/v1/investigate/connection`).

## Validation

Run `npm --prefix web ci`, `npm --prefix web test`, and `npm --prefix web run build`.
For browser checks, install Chromium with `cd web && npx playwright install chromium`, start Vite on port 5173, then run `npm --prefix web run test:browser`.
The Investigation UI workflow builds production assets and runs the same test using intercepted API fixtures. It checks scoped reload, navigation/history, the evidence dialog and focus restoration, workload drill-down, pause, failed refresh retention, empty reports, mobile width, dark theme, and browser errors. Screenshots are uploaded as CI artifacts.

This is the first investigation UX release. Guided policy authoring, effective-policy evaluation, durable incidents, a column-store flow warehouse, SSO/RBAC, and multi-site management remain separate roadmap work. The 7-day flow sidecar is [`flow-log.md`](flow-log.md).

### Against a real controller

`scripts/ci-web-e2e.sh` (job `web-e2e`) builds the UI, runs a real `netrad` serving it, seeds an agent report
and drives it with Chromium with **nothing intercepted**: sign-in is refused for a wrong key or username and
accepted for the right one, all 28 pages load without an uncaught error, a 401 or a request to a missing API path
(the only failures allowed are the documented 502/409s of a controller with no Kubernetes, Hubble or Cilium),
the seeded agent's node and traffic appear on the pages that show them, a deny rule and the enforcement lease
work through the Firewall page, the Audit page shows them, and signing out clears the token. It found and fixed
a real bug: a page that loaded its feeds with `Promise.all` showed nothing when one feed failed (see the
CHANGELOG). Screenshots of every page are uploaded as the `web-e2e-evidence` artifact.
