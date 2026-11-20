# TCX attach modes and XDP Shield

Borrowed from FluxVM’s production attach patterns; Netra keeps Cilium coexistence rules.

## `NETRA_TCX`

| Value | Behavior |
|---|---|
| `auto` (default) | Try TCX attach per configured interface; log and continue if the kernel rejects a hook |
| `off` | Do not attach TCX at all (cgroup hooks still run) |
| `required` | Fail agent startup if any TCX attach fails |

Set via the agent environment (DaemonSet / Helm). Interfaces still come from `NETRA_INTERFACES`.

## XDP Shield

Opt-in per-source PPS protection for dedicated ingress interfaces.

1. List interfaces in `NETRA_XDP_INTERFACES` (never a shared Cilium uplink).
2. Set `NETRA_XDP_SHIELD=true` so the agent attaches `netra_xdp_shield` instead of the generic early-deny XDP program.
3. Publish shield config via `PUT /api/v1/ebpf/shield`, `netractl ebpf shield set`, the `netra_ebpf_shield_set` MCP tool, or the Firewall dashboard page's SHIELD card. All four write the same `EBPFFastPathConfig.shield`:

```json
{
  "mode": "enforce",
  "generation": 1,
  "protectedIpv4": ["10.66.0.10"],
  "protectedIpv6": ["2001:db8::10"],
  "synPps": 5000,
  "udpPps": 20000,
  "icmpPps": 2000,
  "otherPps": 50000,
  "burstSeconds": 2
}
```

Modes: `off` | `audit` (count, pass) | `enforce` (drop when token bucket empty).

Generation is published last so protected-IP maps can be filled before the config flips.

## Safety

- Shield refuses to be useful on empty interface lists.
- Default agent still uses observe-first Netra policy; shield is an additional emergency layer.
- Exact-IP protection covers both `protectedIpv4` and `protectedIpv6` (`shield_protected4`/`shield_protected6`); `protectAll` remains the blanket, non-selective option for either family.

## Per-class and per-source diagnostics

The aggregate `allowed`/`dropped`/`audited` counters Shield always exposed don't say *what kind* of traffic was involved, or *who* it came from. Two additive maps (never resizing the original `shield_stats`/`shield_sources`) fill that in:

- **Per-class breakdown** — the same allowed/dropped/audited counters, broken out by the class Shield already computes internally (`syn`, `udp`, `icmp`, `other`), so a spike shows up as "SYN flood" or "UDP flood" rather than an undifferentiated total.
- **Per-source hit counts** — how many times each source address has been denied, recorded identically whether Shield is in `audit` or `enforce` mode. This lets an operator see who Shield *would* drop before ever flipping it to `enforce`.

Exposed via `GET /api/v1/ebpf/shield`, `netractl ebpf shield`, and the `netra_ebpf_shield` MCP tool. Anomalies: `shield-class-drop-rate` (a class's drop rate is at or above 10%/50%), `shield-source-flood` (a single source has 10,000+ denied hits), and `shield-connection-rate` (a single source has attempted 10,000+ new SYN connections, regardless of Shield's verdict). All three are purely observational — they don't change Shield's own mode or thresholds.

`shield-connection-rate` uses a new `attempts` counter on the existing per-source `shield_source_hits` map, incremented unconditionally for every SYN packet from that source — unlike `denied`, which only increments when the token bucket was empty. This means it can fire even when `syn_pps` is `0` (disabled) or Shield is in `audit` mode, where `denied` (and therefore `shield-source-flood`) never fires at all: a source can be attempting a very high connection rate that Shield isn't configured to act on yet, and this anomaly is the only one of the two that surfaces it. The per-source top-N list (`TopSources`, both agent-side and controller-side) is sorted by `attempts` rather than `denied` for exactly this reason — `attempts` is always `>= denied`, so sorting by it never loses a high-`denied` source and additionally keeps high-`attempts`/zero-`denied` ones a `denied`-only sort would truncate away.

## Deploying interface config with `deploy-remote.sh`

`scripts/deploy-remote.sh` exposes two opt-in env vars, resolved locally before SSH (same reasoning as `NETRA_API_KEY`/`NETRA_AGENT_KEY`: the remote heredoc can't see the invoker's shell environment, so these must be captured on the local side or every deploy silently reverts to empty):

```bash
NETRA_AGENT_INTERFACES=eno8303 NETRA_AGENT_XDP_INTERFACES=eno8303 \
NETRA_API_KEY=<existing key> NETRA_AGENT_KEY=<existing key> \
NETRA_AGENT_ENABLED=true NETRA_WORKLOAD_CONSOLE_ENABLED=true \
./scripts/deploy-remote.sh user@host --quick
```

They map straight to `--set agent.interfaces=...`/`--set agent.xdpInterfaces=...`, which land in `NETRA_INTERFACES`/`NETRA_XDP_INTERFACES` on the DaemonSet (see the top of this doc). Passing the *existing* `auth.apiKey`/`auth.agentKey` (from `helm get values netra -n <ns>`) is required on any redeploy that isn't meant to rotate credentials — `API_KEY_LOCAL`/`AGENT_KEY_LOCAL` mint a fresh random key whenever `NETRA_API_KEY`/`NETRA_AGENT_KEY` aren't supplied, and `helm upgrade` will happily push that over the live secret.

## Verification

On the host:

```bash
sudo kubectl -n netra-system get ds netra-agent -o jsonpath='{.spec.template.spec.containers[0].env}'
sudo kubectl -n netra-system logs ds/netra-agent --tail=80
```

The env output should show the interface name in both `NETRA_INTERFACES` and `NETRA_XDP_INTERFACES`, and the agent's startup log line (`"msg":"Netra standalone datapath attached"`) should list `tcx-egress:<iface>`, `tcx-ingress:<iface>`, and `xdp:<iface>` in its `hooks` array.

Against the API (`Authorization: Bearer <api key>`, not `X-API-Key`):

```bash
curl -sk -H "Authorization: Bearer <key>" https://<host>:30870/api/v1/status   # fastPath.mode
curl -sk -H "Authorization: Bearer <key>" https://<host>:30870/api/v1/ebpf/shield
```

Confirm `fastPath.mode` is still `"observe"` and Shield still shows zero drops before and after — enabling TCX/XDP attach is independent of enforcement; neither this doc's `NETRA_TCX`/`NETRA_XDP_SHIELD` gate nor the global lease change just by attaching the hooks.

In the deployed console (not just the API — the UI is a separate rendering path and can drift from what the backend reports), walk each page that surfaces this state rather than trusting the API alone:

- **Health** → BPF Program Health: shows `N/12 attached` per node and per-hook kernel run counters. `netra_xdp_ingress`'s run count climbing across repeated loads is the strongest signal — it means the program is processing live traffic, not just nominally loaded. `netra_kfree_skb` and `netra_xdp_shield` correctly show `(detached)` when the drop-reason tracepoint is unavailable or Shield is off, respectively.
- **Firewall**: mode toggle reflects `observe`/`enforce` live; Shield card's allowed/dropped/audited counters match the API.
- **Overview**: capabilities panel's `"mode"` field and node-agent packet counters.
- **Hubble**: live flow stream still connects and reports non-zero forwarded flows — confirms Cilium/Hubble weren't disrupted by the redeploy.
- **L7** (if the host is affected by the verifier rejection above): every L7-specific counter should read 0 with no page error, while unrelated counters (e.g. socket attempts) stay populated — that combination is the documented graceful degradation, not a new failure.

A caveat from the one time this was checked end-to-end: the BPF Program Health panel's TCX-hook run counters read 0 even though the agent's startup log confirmed `tcx-egress`/`tcx-ingress` attached. XDP's non-zero, climbing counter is unambiguous; TCX's attach is confirmed by the log line but wasn't independently confirmed by a matching non-zero run counter in that pass. Worth re-checking with a longer observation window or explicit egress/ingress test traffic before treating TCX itself as proven live end-to-end.
