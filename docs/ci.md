# Continuous integration

Every use case Netra ships has a job that runs it for real (a real controller, and where the
use case needs it a real agent, a real kernel, a real cluster or a real browser), not only a
unit test. Each job is a script in `scripts/` that exits non-zero on the first failed
assertion, so the same command runs locally.

## Workflows

| Workflow | When | What |
|---|---|---|
| `ci.yml` | every push to `main`, every pull request, on demand | the jobs below |
| `nightly.yml` | every night, on demand | the expensive checks: the whole suite under `-race`, 10 minutes of fuzzing, the privileged suites on each runner image, multi-arch image builds, two-replica HA. Opens or updates one "Nightly CI is failing" issue on failure |
| `release-dryrun.yml` | pull requests touching Dockerfiles, `bpf/`, `go.mod`, `cmd/`, release files; on demand | everything the tag-triggered `release.yml` does except push, sign and attest: version gates, both images built, the controller and the thin runtime image booted and probed |
| `codeql.yml` | push, pull request, weekly | CodeQL for Go and JS/TS |
| `investigation-ui.yml` | pull requests touching `web/` | the fast browser test with every API call intercepted: sign-in state, the Overview fitting a desktop and a phone viewport, the Connections filters surviving a reload, the evidence drawer, workload drill-down, pause, failure and empty states, and the theme toggle. It runs only on pull requests, so a change pushed straight to `main` is not covered until the next web PR: it went red on every web PR after a redesign for exactly that reason, and its repair found two real UI bugs |
| `release.yml` | version tags | a `verify` job (version files agree, the tag equals the code version), then multi-arch images for the controller and the agent, keyless cosign signatures, SBOM and provenance |
| `pages.yml` | push to `main` | the docs site |

A push to a pull request cancels that pull request's older run. A push to `main` never does:
each `main` commit gets its own concurrency group, because GitHub cancels a *pending* run in a
shared group even with `cancel-in-progress: false`.

## Hygiene gates (in the `go`, `lint`, `security` and `python` jobs)

- `gofmt -l` on every tracked Go file, `shellcheck -S warning` on every script, `go mod tidy`
  leaving `go.mod`/`go.sum` unchanged.
- `golangci-lint` (govet, staticcheck, ineffassign, unused) reporting **only issues a change
  introduces** (`only-new-issues`), so the existing backlog does not block unrelated work.
- `govulncheck` (pinned version, `scripts/ci-govulncheck.sh`): a known-vulnerable dependency the code can reach fails the job, unless the advisory is listed with a reason in `scripts/govulncheck-ignore.txt`. Entries that no longer match are reported as stale; remove them.
- The LangGraph companion's tests (`make test-python`, minimum test count).
- Dependabot opens weekly update PRs (Go, npm for `web/` and `website/`, Actions, Docker, pip). Actions
  arrive as one grouped PR and the `ubuntu` base of the agent image is ignored: a base-image change decides
  glibc, clang and the kernel-facing tooling, so it is a deliberate migration. Every update PR runs the full
  CI; read `main` after merging a major bump.

## Use cases and the job that proves each

| Use case | Job | Script | Level |
|---|---|---|---|
| Deny/allow/CIDR/port rules drop packets, only what they name; IPv6; lease expiry; controller-death fail-open | `enforce-veth` | `ci-enforce-veth.sh` | real agent, real kernel |
| Manual packet capture on both backends: filter, both directions, `.pcap` validity, stop/history | `capture-live` | `ci-capture-live.sh` | real agent, real kernel |
| Datapath sensors (HTTP status, TLS fingerprints, sampled L7, TLS plaintext) | `http-status-smoke`, `tlsfp-smoke`, `l7sample-smoke`, `tlssample-smoke` | `ci-*-smoke.sh` | real agent, real kernel |
| eBPF programs and verifier, x86_64 and arm64 | `ebpf`, `ebpf-arm64` | `ci-ebpf-tests.sh` | real kernel |
| Flow observability and auto-capture | `flow-observe-veth`, `auto-capture-veth` | `ci-flow-observe-veth.sh`, `ci-auto-capture-veth.sh` | veth |
| Netlink change recorder: ring and delivery cursor, resubscribe after ENOBUFS, controller history | `go` job | `ci-netlink-unit.sh` | unit + race |
| Deploy guards: disk warning/refusal, image re-import after kubelet image GC, readiness wait, and the rendered remote script's ordering | `go` job | `ci-deploy-guards.sh` | stubbed df/k3s/kubectl |
| BPF attachment inventory and hook drift: owners, kernel-truncated names, unchanged-summary protocol, controller carry-forward | `go` job | `ci-bpfattach-unit.sh` | unit + race |
| BPF attachment inventory against a real kernel: real TCX/XDP/cls_bpf attachments, a detached hook, a recreated interface | `ebpf` job | `ci-ebpf-tests.sh` | real kernel |
| Netlink change recorder against a real kernel: veth address/route/neighbor/MTU changes, forced overrun | `netlink-veth-smoke` | `ci-netlink-veth.sh` | real kernel, throwaway netns |
| Agent to controller mutual TLS | `mtls-smoke` | `ci-mtls-smoke.sh` | real controller and agent |
| OIDC login and RBAC | `oidc-live` | `ci-oidc-live.sh` | real controller |
| MCP server (tools, gating, audit actor) | `mcp-live` | `ci-mcp-live.sh` | real controller and MCP server |
| State survives restart; lease never resurrected; corrupt state refused | `persistence-live` | `ci-persistence-live.sh` | real controller |
| Alert and export sinks: webhook, Slack, Teams, bridge, SMTP, OTLP, syslog | `sinks-live` | `ci-sinks-live.sh` | real controller, real receivers |
| Loki push | `loki-live` | `ci-loki-live.sh` | real Loki |
| Workload metrics and SLOs | `workload-obs-live`, `prometheus-rules` | `ci-workload-obs-live.sh`, `ci-prometheus-rules.sh` | real controller, promtool |
| `netractl`, every command including the mutating ones | `go` job | `ci-netractl-commands.sh`, `ci-netractl-live.sh` | mock catalog and real controller |
| `netra-doctor` | `doctor-live` | `ci-doctor-live.sh` | the runner itself |
| Web UI against a real controller | `web-e2e` | `ci-web-e2e.sh` | real controller, real browser |
| Helm chart renders, guard rails, opt-ins | `helm` | inline | `helm template` |
| Install, upgrade from the previous release, agent DaemonSet, restart, rollback | `kind-lifecycle` | `ci-kind-lifecycle.sh` | real cluster (kind) |
| The plain manifests (`kubectl apply -k deploy/`) | `manifests-kind` | `ci-manifests-kind.sh` | real cluster (kind) |
| Two-replica HA, leader election, failover | `ha-kind` (nightly) | `ci-ha-kind.sh` | real cluster (kind) |
| Images build and the agent image ships every BPF object | `agent-image`, `release-dryrun` | `ci-agent-image.sh` | container build |
| A release would succeed (version gates, both images, the thin runtime image boots) | `release-dryrun.yml` | inline | container build and boot |
| The UI a controller serves is complete: every file in `web/public` and every asset the page references, byte for byte (an unknown path answers 200 with the HTML fallback, so a missing logo passes every health probe) | `release-dryrun.yml`, `kind-lifecycle` | `check-served-ui.sh` | the built images, running |

Not covered by CI: a real Cilium/Hubble (the chart's Cilium mode is checked by `helm template`
only), and the shared lab host (never a CI target).

## What the kernel and cluster jobs assume

- The runner kernel is not selectable. `nightly.yml` runs the privileged suites on
  `ubuntu-24.04`, `ubuntu-24.04-arm` and (informational) `ubuntu-22.04`, and prints each kernel,
  so a verifier or feature difference is tied to a version. `docs/l7-metadata.md` records one that
  the newest runner would never show.
- A kind node is a container with no bpffs; the lifecycle and manifest scripts mount it, as an
  operator's node image would. The HA script makes its shared hostPath writable for the
  non-root controller.
- `kind-lifecycle` needs a previous release tag (`git fetch --tags`); it builds that release from
  source with the current Dockerfile, so an old Dockerfile that no longer builds cannot hide an
  upgrade problem. "Previous" means the newest tag with a **different version** than the checkout, so
  commits on top of a fresh tag (same version) still upgrade from the release before it. With no release
  tag at all there is nothing to upgrade from: CI sets `ALLOW_NO_PREVIOUS_TAG=1`, so the job ends with a
  warning annotation ("kind-lifecycle skipped") instead of failing, and the install, upgrade and rollback
  test does not run until a `vX.Y.Z` tag exists. A local run without that variable still fails.

## Running a job locally

Most need only Go and curl. The ones that need root and Linux say so at the top of the script.

```sh
./scripts/ci-mcp-live.sh                 # any OS
./scripts/ci-persistence-live.sh         # any OS
./scripts/ci-sinks-live.sh               # any OS (python3)
sudo ./scripts/ci-enforce-veth.sh        # Linux, root, clang
sudo ./scripts/ci-capture-live.sh        # Linux, root, clang
./scripts/ci-kind-lifecycle.sh           # a running kind cluster, docker, helm
./scripts/ci-web-e2e.sh                  # node with Playwright's chromium installed
```

`scripts/lib/veth-lab.sh` is the shared setup for the real-agent scripts (controller, agent, veth
pair into a namespace, servers). `KEEP=1` keeps a script's temp directory for inspection.

## Cutting a release

A release is a tag; everything that can be checked is checked before it.

1. Bump the version everywhere (`cmd/netrad/main.go` is the reference; the gate in
   `scripts/check-version-sync.sh` checks `web/package.json`, `internal/api/server.go`, the Helm
   `Chart.yaml` and `values.yaml`, `deploy/agent.yaml` and `deploy/controller.yaml`; bump
   `web/package-lock.json` with it, which the gate does not check) and give `CHANGELOG.md` a
   `## X.Y.Z — date` heading, which the gate requires. `deploy-remote.sh` is a deliberate exception.
2. `./scripts/check-version-sync.sh`, then push and wait for `ci.yml` to be green on the exact commit.
3. Run the dry run on that commit: `gh workflow run release-dryrun.yml --ref main`. It does everything
   `release.yml` does except push and sign, so a broken Dockerfile or a missing BPF object fails here
   and not on the tag.
4. Tag that commit: `git tag -a vX.Y.Z -m "Netra X.Y.Z" <sha> && git push origin vX.Y.Z`. The tag cannot be
   moved afterwards without re-publishing images, so it goes on a commit CI has already verified.
5. Watch `release.yml`, then check the result yourself rather than trusting the green run: both images have
   an `X.Y.Z` tag in `ghcr.io`, each digest has a `sha256-<digest>.sig` signature tag beside it, and the
   signing certificate names `release.yml@refs/tags/vX.Y.Z` and the commit
   (see [Install from a release](../deploy/README.md#install-from-a-release)).
6. Install it: pull the released images (not a source build) with the chart from the tag, compare the
   running pods' `imageID` with the release digests, and run the API checks (session cookie, status,
   agents, exports) against the released build.

`0.28.0` is the first release cut this way and the first published to `ghcr.io`: `release.yml` was added
after `v0.27.97` was tagged, and `0.27.98` to `0.27.111` were deployed from source but never tagged.

## Adding a job

1. A script in `scripts/` that fails loudly, asserts a minimum count of what it expects, and
   cleans up with a bounded reaper (a process that ignores SIGTERM must not hang the job).
2. **Break the thing and watch it fail** before trusting it, and read the real output once by eye:
   two counting defects here passed assertions and were found only by reading the output.
3. Iterate kernel and cluster jobs on a throwaway branch with a dev-only workflow before landing
   them (there is no local Linux kernel in the maintainers' setup).
4. `timeout-minutes` on the job, and a line in the table above.
