# netractl — operator CLI

Cilium-style CLI for Netra: install the cluster, check status, toggle
features, and drive day-2 observe/enforce workflows.

## Install the CLI onto PATH

```bash
make install                         # → /usr/local/bin/netractl
make install PREFIX=$HOME/.local     # → ~/.local/bin/netractl
make uninstall

# or from an already-built binary:
netractl install-cli
netractl install-cli --prefix $HOME/.local
```

`scripts/deploy-remote.sh` also installs `netractl` to `/usr/local/bin` (or
`~/.local/bin`) after building. `netractl install` (Helm lifecycle) copies
itself onto PATH as well; use `--skip-cli` to opt out.

## First commands after cluster install

```bash
netractl --help           # colorful grouped help on a TTY (NO_COLOR / NETRA_CLI_COLOR=false to disable)
netractl status
netractl features list
netractl features enable dns-detect --yes
netractl pods | netractl vms | netractl workload Pod default my-pod
netractl fleet | netractl fleet flows --limit 50
netractl capture history | capture summaries
```

## Self-signed TLS and `~/.netra`

Helm and plain manifests enable **HTTPS with a self-signed cert by default**.
Browsers warn; CLI clients must either skip verify or trust the CA.

`netractl` is wired for that default:

| Source | Behavior |
|--------|----------|
| `~/.netra/env` | Key=value file loaded automatically (does not override already-set env vars). Written by `deploy-remote.sh`. |
| `~/.netra/api-key` | Used as `NETRA_API_KEY` when that env var is unset. |
| Loopback URL | If `NETRA_URL` is `https://127.0.0.1` / `localhost` / `::1` and `NETRA_TLS_INSECURE` is **unset**, skip TLS verify automatically. |
| Explicit | `NETRA_TLS_INSECURE=false` always verifies. `=true` always skips. |

Example `~/.netra/env` (created by deploy):

```bash
NETRA_URL=https://212.8.248.187:30870
NETRA_TLS_INSECURE=true
NETRA_API_KEY=<key from ~/.netra/api-key on the host>
```

Manual equivalent:

```bash
export NETRA_URL=https://<node-ip>:30870
export NETRA_TLS_INSECURE=true
export NETRA_API_KEY=$(cat ~/.netra/api-key)
netractl status
```

If you see `x509: certificate signed by unknown authority`, set
`NETRA_TLS_INSECURE=true` (or point `NETRA_URL` at loopback / use `~/.netra/env`).

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NETRA_URL` | `https://127.0.0.1:30870` | Controller base URL |
| `NETRA_API_KEY` | from `~/.netra/api-key` if present | Bearer token |
| `NETRA_TLS_INSECURE` | auto on loopback; else false | Skip TLS verify for chart self-signed cert |
| `NETRA_CLI_NO_BANNER` | unset | Set any value to hide the Zyvor banner |
| `NETRA_CLI_COLOR` | auto on TTY | `false` / `0` disables color; `NO_COLOR` also disables |
| `NETRA_CLI_PREFIX` | unset | Default prefix for `install-cli` / post-Helm CLI copy |
| `NETRA_CHART` | `./helm/netra` | Helm chart path for `install` / `upgrade` / `features` |
| `NETRA_NAMESPACE` | `netra-system` | Helm / kube namespace |
| `NETRA_RELEASE` | `netra` | Helm release name |

## Cluster lifecycle

```bash
netractl install --namespace netra-system
netractl upgrade
netractl uninstall --yes
```

Defaults on install: `agent.enabled=true`, `tls.enabled=true`, generated
`auth.apiKey` / `auth.agentKey`, CLI installed onto PATH. Flags:
`--chart`, `--node-port`, `--api-key`, `--agent-key`, `--cli-prefix`,
`--skip-cli`, `--set k=v`.

## Status

```bash
netractl status           # human board + banner on TTY
netractl status --json
netractl status --wait    # retry until healthy
```

Shows version, datapath, mode, Cilium/Hubble, lease, agents, feature
on/off counts, and per-node hooks.

## Features

See [`features.md`](features.md). Short form:

```bash
netractl features list
netractl features enable NAME --yes    # Helm --reuse-values --set …
netractl features disable NAME --yes
netractl features enable NAME --yes --api   # live env patch via API
```

## Dashboard login

Same bearer as the CLI: sign in as `admin` with the API key as the password. See [`dashboard-login.md`](dashboard-login.md).

## Datapath maps

Inspect what the controller has staged into Netra’s BPF maps (desired state
agents sync under `/sys/fs/bpf/netra`):

```bash
netractl ebpf maps          # human board (deny / allow / rate / policy / …)
netractl ebpf maps --json
```

Full reference: [`ebpf-maps.md`](ebpf-maps.md). Related:

```bash
netractl ebpf census        # counts only
netractl ebpf coverage      # programs + missing pins per node
netractl ebpf scope show    # raw config JSON
netractl ebpf rules list    # durable rule IDs
```

## CI and full remote verification

Every catalogued `netractl` command (read paths plus representative mutates)
is exercised against an httptest mock in CI:

```bash
./scripts/ci-netractl-commands.sh   # or: make test-netractl-commands
```

GitHub CI also boots a local, throwaway `netrad` and runs the full detailed board
(not a short smoke), **including the mutating commands** (146 pass, 1 streaming command skipped),
then `hack/smoke.sh` and `examples/siem-export.sh` in every format:

```bash
./scripts/ci-netractl-live.sh       # or: make test-netractl-live
```

Against a real lab (after `~/.netra/env` or `NETRA_URL` / `NETRA_API_KEY` /
`NETRA_TLS_INSECURE`):

```bash
./scripts/ci-netractl-remote.sh
# optional: NETRA_CLI_ALLOW_MUTATE=1 ./scripts/ci-netractl-remote.sh
```

Mutating examples are skipped on the remote suite by default so the lab
stays observe-first.

## Related

- [`features.md`](features.md) — feature catalog, API, UX
- [`ebpf-maps.md`](ebpf-maps.md) — read-only map inventory (`ebpf maps`)
- [Install · Standalone Helm install](install.md#standalone-helm-install)
- [Architecture · HTTPS default](architecture.md#https-default)
