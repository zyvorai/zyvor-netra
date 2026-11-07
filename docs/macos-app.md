<!-- Copyright 2026 Zyvor AI Labs · https://zyvor.dev -->
<!-- SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0 -->

# macOS app

A native macOS client for a Netra controller, in `macos/` (SwiftUI, macOS 15+, Swift package).
It is a client of the existing `/api/v1/*` API and nothing else: it ships no agent, adds no
server route and does not talk to PacketWolf. Observe pages are read-only; the few control
surfaces go through one safety gate (below).

Two targets: `NetraKit` (API client, certificate pinning, Keychain, SSE parsing, the safety
model and the pure data mappers, all unit tested) and `Netra` (the app).

## Build and run

```bash
cd macos
swift build
swift run Netra
swift test
```

Packaging, signing and notarization are not done (see Known gaps); `macos/Packaging/Info.plist`
is the only packaging input so far.

## Connect and certificate pinning

Enter the controller URL (default port 30870) and a bearer token. The token is stored in the
macOS Keychain, never on disk in plain text and never in the activity log.

Controllers usually present a self-signed certificate, so the app uses trust on first use
(TOFU):

- A certificate the system already trusts is accepted.
- Otherwise the app probes the controller, shows the leaf SHA-256 fingerprint, and pins it for
  that `host:port` only after you accept it.
- A pinned host whose certificate later changes, and is not system-trusted, is a hard failure
  (mismatch), not a prompt to re-trust by accident.

## Safety model

The server stays authoritative; the client mirrors its rules so the UI cannot be less careful.

- Read-only tokens: `/api/v1/whoami` reports whether the token can mutate. `MutationGate`
  blocks every mutating action when it cannot.
- `MutationFlow`: every mutation is previewed first (a dry run or a read) and must succeed
  before execute is offered.
- Typed confirmation: high-risk actions require typing an expected phrase, and only then send
  `X-Netra-Confirm-Risk: high`.
- Leases: enforce is lease-bounded and fails open to observe. `LeaseTracker` shows the time
  remaining and treats an expired enforce lease as observe.
- Activity log: every attempted mutation (blocked, attempted, succeeded, failed) is kept in
  memory only, up to 500 entries, without tokens.
- Policy apply keeps the server's plan-token plus risk-confirm rule; the threat-feed and
  security-review surfaces stay read-only. Netlink, BPF attachment and map pages only read.

## Pages by sidebar group

The inventory is `NavSection` and `SectionGroup.all` in `macos/Sources/Netra/Sections.swift`;
`PageRouter` sends each section to a bespoke view, and anything without one falls back to a
generic JSON browser.

| Group | Pages |
|---|---|
| Now | Overview, Health, Scorecard, SLO |
| Traffic | Flows, Talkers, Ports, Protocols, Drops, DNS, Topology, TCP events, Connections, Path & ICMP, Congestion |
| Workloads | Workloads, Pods, L7, TLS fingerprints |
| Kernel | Diagnostics, Listen queues, Sysctl audit, Node resources, Netlink, BPF attachments, BPF maps, IPv6, Kernel network, eBPF coverage |
| Detect | Metrics, Metric contexts, Anomalies, Alerts, Insights, Incidents, Security, Intel, Explain, Investigate, Optimizer, Playbooks, Baselines |
| Record | Audit, Compliance, Report |
| Ask Netra | Brief, Digest, Suggestions |
| Platform | Agents, Surfaces, Exports, Artifacts, GitOps, Tenants |
| Control | Lease, Rules, Policies, Features, Capture, Enforcement, Fleet |

Kernel network shows findings with evidence, and the suggested sysctl, apply and rollback
commands only as text to copy; the app never changes a kernel tunable.

Beyond the sidebar: a menu bar item, a command palette, notifications for raised metric
alerts, deep links, and Spotlight indexing.

## Route coverage

`scripts/ci-macos-route-coverage.sh` lists every `/api/v1/...` route registered with
`mux.Handle` or `mux.HandleFunc` and checks that each is referenced under `macos/Sources`
(`{name}` segments match any one segment; a trailing `/` matches as a prefix) or is waived in
`macos/route-waivers.txt` with a reason (`VERB /path # reason`). It exits non-zero while any
route is uncovered, and warns about waivers that name no registered route. Matching is by
path only, so an unused verb on a referenced path is not caught. Waive only what is not a
client concern (agent-only ingest, browser session routes); do not waive a route to go green.
It is not yet a CI step.

## Known gaps

- Not live-verified: built and unit tested, but not exercised against a running controller
  across every page.
- No packaging, code signing or notarization; no installer.
- No OIDC sign-in yet; authentication is a bearer token.
- Some API routes have no page yet; the route-coverage script prints the current list.
- No macOS CI job is defined yet.
