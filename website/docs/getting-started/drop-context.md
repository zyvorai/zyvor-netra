---
sidebar_position: 3
---

# Drop incident context

When a critical packet drop starts an automatic capture, Netra keeps the
PCAP and a JSON snapshot taken at the same moment: which node, whether CPU
or memory was hot, the top workloads, and a short process list. The process
list is comm, pid, CPU, and RSS only. Netra does not store command lines,
environments, or Secret contents, and it does not collect a sosreport.

The full walkthrough, including the API and the iperf3 check, is in the
repository at `docs/tutorials/drop-incident-context.md`. The steps below
are enough to turn it on and read one incident.

## Turn it on

Automatic capture is off by default. Context files are written only for
those automatic sessions.

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system \
  --reuse-values \
  --set alerting.autoCapture.enabled=true
```

A capture starts on a critical softnet drop (at least 1000), a critical
drop-rate spike, or a critical Congestion Map finding. Warning-only
interface and qdisc counters do not start one. The same node will not
start a second capture until the cooldown passes (default 10 minutes).

## Read it in the console

1. Open **Investigate → Capture**.
2. In history, open the row badged **Auto**.
3. **Download** is the PCAP.
4. **Context** is the JSON. It is shown only when a snapshot was stored.

If the PCAP is empty, Netra deletes it and deletes the context with it.

## Read it from the API

`~/.netra/env` already has the controller URL and API key after install.

```bash
set -a
. ~/.netra/env
set +a

curl -skf -H "Authorization: Bearer ${NETRA_API_KEY}" \
  "${NETRA_URL}/api/v1/capture/history?limit=20" \
  | jq '.entries[] | select(.contextAvailable) | {node,artifactId,artifactFrames,triggerKind}'
```

Then, with the id from that list:

```bash
curl -skf -H "Authorization: Bearer ${NETRA_API_KEY}" \
  "${NETRA_URL}/api/v1/capture/artifacts/${ID}/context" \
  | jq '{node,cpuHot,memoryHot,topProcessesByCpu,topWorkloadsByCpu}'
```

`cpuHot` means the last sample was at least 80% of the node's cores, not
that the raw `cpuPercent` number crossed 80. A full 8-core node reads
about 800. `memoryHot` means at least 90% of memory was in use. Both
numbers are the last agent sample, about 3 seconds old, not a long baseline.

## Prove it with iperf3

On a Linux host, as root, from a checkout of this repository:

```bash
sudo ./scripts/ci-auto-capture-veth.sh
```

The script builds a veth pair, runs iperf3 across it, triggers a critical
softnet drop, and checks that the PCAP and the context JSON both exist.
The context must name that live iperf3 process. GitHub runs the same
script as the `auto-capture-veth` job.
