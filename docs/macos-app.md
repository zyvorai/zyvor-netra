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
| Ask Netra | Brief, Digest, Suggestions (the Ask panel has an Agent mode) |
| Platform | Agents, Surfaces, Exports, Artifacts, GitOps, Tenants |
| Control | Lease, Rules, Policies, Features, Capture, Enforcement, Fleet |

Kernel network shows findings with evidence, and the suggested sysctl, apply and rollback
commands only as text to copy; the app never changes a kernel tunable.

The Ask panel's Agent mode calls `POST /api/v1/ai/agent` and shows the answer, the step trace
(classify, draft, synthesize) and cited evidence as read-only text; a drafted rule is a text
preview with no apply path. The Explain page has an "Explain in words" button for
`POST /api/v1/ai/explain`. Neither request carries a risk confirmation.

Beyond the sidebar: a menu bar item, a command palette, notifications for raised metric
alerts, deep links, and Spotlight indexing.

## Route coverage

`scripts/ci-macos-route-coverage.sh` lists every `/api/v1/...` route registered with
`mux.Handle` or `mux.HandleFunc` and checks that each is referenced under `macos/Sources`
(`{name}` segments match any one segment; a trailing `/` matches as a prefix) or is waived in
`macos/route-waivers.txt` with a reason (`VERB /path # reason`). It exits non-zero while any
route is uncovered, and warns about waivers that name no registered route. Matching is by
path only, so an unused verb on a referenced path is not caught. Paths the app builds
dynamically (the rule-mutation family in `NetraKit/API/RuleKinds.swift` and
`api/v1/export/<kind>` in `OpsData.swift`) cannot be grepped, so they are listed in
`macos/route-dynamic.txt` (`VERB /path # builder: file`).
`Tests/NetraKitTests/RouteCoverageTests.swift` enumerates every kind, action and removal and
asserts the file equals exactly what the builders produce, so a listed route is one the app
really sends. The script prints literal, dynamic, waived and uncovered counts. Waive only what is not a
client concern (agent-only ingest, browser session routes); do not waive a route to go green.
It runs in CI as a step of `.github/workflows/macos.yml`. Two routes are waived pending a page: `GET /api/v1/handoff` and the capture WebSocket relay `GET /api/v1/vms/{node}/capture/ws` (a separate, commented waiver line to delete once the app covers it).

## Packaging and release

Local build (macOS, Xcode command line tools):

```bash
macos/Packaging/build-app.sh   # macos/dist/Netra.app: release build, universal arm64+x86_64 when the toolchain allows
macos/Packaging/make-dmg.sh    # macos/dist/Netra.dmg
```

`build-app.sh` falls back to the host architecture with a printed note if the universal build fails.
Version comes from `git describe` (or `NETRA_VERSION`), build number from the commit count (or `NETRA_BUILD`);
`OUT_DIR`, `BUILD_PATH` and `UNIVERSAL=0` are also honoured. The bundle is signed with
`CODESIGN_IDENTITY` (default ad-hoc `-`), hardened runtime, and `Packaging/Netra.entitlements`. An app icon is
included only if `Packaging/Netra.icns` exists; none is shipped yet. `make-dmg.sh` signs the dmg when the identity is not
ad-hoc and notarizes (`notarytool submit --wait`, `stapler staple`, then `spctl --assess`) only when `NOTARY_*` variables
(`NOTARY_KEYCHAIN_PROFILE`, or `NOTARY_APPLE_ID`/`NOTARY_TEAM_ID`/`NOTARY_PASSWORD`, or `NOTARY_API_KEY_PATH`/`NOTARY_API_KEY_ID`/`NOTARY_API_ISSUER`) are set;
otherwise it says so and skips. No certificate or credential is in the repository.

Entitlements: App Sandbox, `network.client` (controller HTTPS and WebSocket), `files.user-selected.read-write`
(NSSavePanel exports). The Keychain (token, TLS pins) and UserNotifications need none. Sandbox caveats to check on a
signed build: "Open in Wireshark" launches `/Applications/Wireshark.app` via NSWorkspace and hands it a pcap written to
the temporary directory (the sandbox container's own tmp); Wireshark, being outside the sandbox, may be unable to read that container path.
Connecting to a controller on the local network may show the macOS Local Network prompt. Neither has been verified.

CI: `.github/workflows/macos.yml` (build, test, route coverage) on changes under `macos/`.
`.github/workflows/macos-release.yml` runs on tag `macos-v*` or manual dispatch, uploads the dmg as an artifact and, on a tag,
attaches it to a draft GitHub release. Signing and notarization happen only when these repository secrets exist:

| Secret | Purpose |
|---|---|
| `MACOS_CERT_P12_BASE64` | base64 Developer ID Application certificate and key (.p12) |
| `MACOS_CERT_PASSWORD` | password of the .p12 |
| `MACOS_SIGN_IDENTITY` | identity name, e.g. `Developer ID Application: Name (TEAMID)` |
| `NOTARY_API_KEY_BASE64` | base64 App Store Connect API key (.p8) |
| `NOTARY_API_KEY_ID`, `NOTARY_API_ISSUER` | API key id and issuer id |

Not verified: Developer ID signing, notarization, stapling and Gatekeeper assessment (need secrets), the release workflow itself
(never run), sandboxed runtime behaviour beyond launch, and a Developer ID build on a clean Mac.

Deployment target: `Package.swift` and `Info.plist` say macOS 15. The build machine used for this change has Xcode 27.2
(SDK 27.2), so newer SDKs are available; the target was deliberately not raised.

## Known gaps

- Not live-verified: built and unit tested, but not exercised against a running controller
  across every page.
- Packaging scripts exist (see Packaging and release) but signing and notarization are untested without secrets.
- No OIDC sign-in yet; authentication is a bearer token.
- Some API routes have no page yet; the route-coverage script prints the current list.
