# Netra host readiness (`netra-doctor`)

`netra-doctor` is a read-only preflight command for Netra's standalone eBPF node agent. It helps operators determine whether a Linux host has the kernel, cgroup, bpffs, tracepoint and privilege prerequisites Netra expects **before** deploying the privileged agent.

It never mounts filesystems, changes sysctls, loads BPF programs, attaches hooks, or mutates network state.

## Build

```bash
go build ./cmd/netra-doctor
```

## Basic check

```bash
sudo ./netra-doctor
```

The command exits with code `0` when no required check fails and `2` when one or more checks fail.

Warnings are advisory by default. For CI or provisioning gates, make warnings fatal:

```bash
sudo ./netra-doctor --strict
```

## Optional feature gates

Netra's default standalone path is cgroup v2. TCX and kernel skb drop-reason tracing are optional. If a deployment intends to use them, require them explicitly:

```bash
sudo ./netra-doctor --require-tcx --require-drop-reasons
```

`--require-tcx` requires Netra's practical Linux `6.6+` TCX baseline.

`--require-drop-reasons` requires an `skb:kfree_skb` tracepoint whose format exposes a `reason` field. This matches Netra's observe-only v0.14 drop diagnostics guard: hosts that cannot prove the field exists should not report fabricated kernel drop reasons.

## JSON output

```bash
sudo ./netra-doctor --json
```

Example shape:

```json
{
  "os": "linux",
  "architecture": "arm64",
  "kernelRelease": "6.8.0",
  "checks": [
    {
      "id": "cgroup-v2",
      "title": "cgroup v2",
      "status": "pass",
      "detail": "5 controllers visible"
    }
  ],
  "summary": {
    "pass": 12,
    "warn": 2,
    "fail": 0,
    "info": 1
  }
}
```

The JSON format is suitable for image-build validation, Ansible/Terraform wrappers, Kubernetes node admission workflows, and support bundles.

## Checks

The first release validates:

- Linux and architecture (`amd64`/`arm64` are the normal targets);
- Linux `5.8+` core baseline and optional `6.6+` TCX baseline;
- cgroup v2 controller and unified membership visibility;
- bpffs mounted at `/sys/fs/bpf`;
- kernel BTF availability;
- tracefs availability;
- optional `skb:kfree_skb` drop-reason field support;
- effective BPF/network-related Linux capabilities;
- `kernel.unprivileged_bpf_disabled` posture;
- kernel lockdown mode;
- live-host `RLIMIT_MEMLOCK`;
- UP non-loopback interfaces that may be candidates for optional TCX/XDP attachment.

## Inspecting a mounted support bundle

Most filesystem checks can run against a different root:

```bash
./netra-doctor --root /mnt/support/node-17 --json
```

When `--root` is not `/`, checks that require the running process rather than filesystem evidence (currently memlock and live interface enumeration) are reported as `info`/skipped instead of producing misleading results.

## Safety boundary

A successful doctor report means the visible host prerequisites look compatible. It is **not** proof that every BPF program will attach: vendor kernels, LSM policy, container runtime restrictions, interface/driver XDP capabilities, and local security policy can still reject an operation. Netra should continue to fail open and report hook-level attachment state at runtime.

## Verification in CI

`scripts/ci-doctor-live.sh` (job `doctor-live`, and every nightly kernel leg) builds the real binary and
checks it against an empty filesystem root (must fail loudly: exit 2, every failing check carries
remediation, the JSON and human summaries agree) and, on Linux as root, against the runner itself
(kernel, TCX, cgroup v2, bpffs, BTF, tracefs and drop-reason support all present; `-strict` exits
non-zero exactly when there are warnings). Root matters: tracefs and the BPF filesystem are not
readable without it, and the agent runs privileged.
