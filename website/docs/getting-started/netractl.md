---
sidebar_position: 2
---

# netractl CLI

Install the CLI, talk to a self-signed HTTPS controller, and run status /
features without hand-exporting env vars every time.

## Install onto PATH

```bash
make install                         # → /usr/local/bin/netractl
make install PREFIX=$HOME/.local     # → ~/.local/bin/netractl
make uninstall

netractl install-cli                 # from an already-built binary
```

`deploy-remote.sh` and `netractl install` also place `netractl` on PATH
(opt out of the Helm path with `--skip-cli`).

## After install — just run status

```bash
netractl status
netractl features list
```

## Self-signed TLS (`x509: unknown authority`)

The chart enables HTTPS with a **self-signed** cert by default. `netractl`
handles that:

1. Loads `~/.netra/env` (if present) without overriding your shell exports.
2. Loads `~/.netra/api-key` into `NETRA_API_KEY` when unset.
3. For loopback URLs (`127.0.0.1` / `localhost`), skips TLS verify when
   `NETRA_TLS_INSECURE` is unset.
4. `deploy-remote.sh` writes `~/.netra/env` with `NETRA_URL`,
   `NETRA_TLS_INSECURE=true`, and the API key.

Manual:

```bash
export NETRA_URL=https://<node-ip>:30870
export NETRA_TLS_INSECURE=true
export NETRA_API_KEY=$(cat ~/.netra/api-key)
netractl status
```

Set `NETRA_TLS_INSECURE=false` when you terminate TLS with a trusted cert.

## Common commands

```bash
netractl install --namespace netra-system
netractl status [--json] [--wait]
netractl upgrade
netractl uninstall --yes
netractl features list
netractl features enable dns-detect --yes
netractl ebpf summary
netractl ebpf maps              # datapath map inventory (human)
netractl ebpf maps --json
netractl ebpf census            # counts only
netractl ebpf coverage
netractl flows history --since 1h
netractl insights red 5m
netractl insights traces 15m
netractl insights profiles
netractl insights workload-events
netractl insights kernel-notes
netractl ai brief
```

Flow history, RED, traces, stacks, kernel notes, and pod warnings:
[`docs/flow-log.md`](https://github.com/zyvorai/zyvor-netra/blob/main/docs/flow-log.md).

Map inventory details:
[`docs/ebpf-maps.md`](https://github.com/zyvorai/zyvor-netra/blob/main/docs/ebpf-maps.md).
Full feature catalog and dashboard toggles: see the repo doc
[`docs/features.md`](https://github.com/zyvorai/zyvor-netra/blob/main/docs/features.md).
Dashboard sign-in: `admin` / `Admin@321` when the API key matches that demo
token (or paste the real `auth.apiKey` as the password).
