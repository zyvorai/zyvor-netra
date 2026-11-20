# Tutorials: drop incident context

When auto-capture starts on a critical packet drop, Netra writes two files:
the PCAP, and a sibling JSON snapshot of the node at that moment. The JSON
is the part these tutorials cover. It names the node, whether CPU or memory
was hot, the top workloads, and a short comm-only process list. It is not a
Red Hat sosreport: no `dmesg`, journal, package inventory, argv, or Secret
contents.

Reference for the capture itself: [capture.md](../capture.md). These pages
are the walkthroughs.

## 1. Turn collection on

Auto-capture is off until you enable it. Context is written only for
sessions that auto-capture starts. An operator-started capture on the
Capture page does not freeze a context file.

Helm:

```bash
helm upgrade --install netra ./helm/netra \
  --namespace netra-system \
  --reuse-values \
  --set alerting.autoCapture.enabled=true
```

Or set the controller environment directly:

```bash
export NETRA_AUTO_CAPTURE=true
export NETRA_AUTO_CAPTURE_DURATION=60s
export NETRA_AUTO_CAPTURE_DIR=/var/lib/netra/auto-capture
```

Restart the controller after an env change. Confirm the process is the
leader if you run more than one replica: only the leader starts captures
and writes the directory.

What starts a capture, and therefore a context file:

| Signal | When |
|---|---|
| Softnet drops | Critical, cumulative dropped count at least 1000 |
| Kernel or policy drop-rate spike | Critical (large jump versus the recent average) |
| Congestion Map finding | Severity critical |

Warning-only signals (interface drops, qdisc drops, time-squeeze) do not
start a capture. A second critical signal on the same node inside the
cooldown (default 10 minutes) does not start another one.

## 2. Read an incident in the console

1. Open **Investigate → Capture**.
2. In **Capture history**, find a row with the **Auto** badge. The badge
   text includes the trigger, for example `dropdiag/softnet-drop`.
3. **Download** saves the PCAP. Open it in Wireshark or `tcpdump -r`.
4. **Context** appears only when that session froze a JSON file. Save it
   next to the PCAP and read it with `jq`.

If the row has **Download** but no **Context**, the capture finished
before this feature was deployed, or the PCAP was empty and both files
were discarded. A header-only PCAP is not kept, and neither is its context.

## 3. Read the same incident from the API

Use the URL and API key already in `~/.netra/env` (written by a normal
install). Do not put a host address in the command.

```bash
set -a
. ~/.netra/env
set +a

curl -skf -H "Authorization: Bearer ${NETRA_API_KEY}" \
  "${NETRA_URL}/api/v1/capture/history?limit=20" \
  | jq '.entries[] | select(.contextAvailable) | {node,requestor,artifactId,artifactFrames,triggerSource,triggerKind}'
```

Copy `artifactId` from that list, then:

```bash
ID=the-artifact-id

curl -skf -H "Authorization: Bearer ${NETRA_API_KEY}" \
  "${NETRA_URL}/api/v1/capture/artifacts/${ID}" \
  -o "${ID}.pcap"

curl -skf -H "Authorization: Bearer ${NETRA_API_KEY}" \
  "${NETRA_URL}/api/v1/capture/artifacts/${ID}/context" \
  -o "${ID}.context.json"

jq '{node,cpuHot,memoryHot,topProcessesByCpu,topWorkloadsByCpu,trigger}' \
  "${ID}.context.json"
```

On the controller host the same JSON is the file
`/var/lib/netra/auto-capture/<artifact-id>.context.json` beside the
`.pcap`. Pruning an old PCAP deletes the JSON with it.

## 4. Read the JSON

A trimmed incident looks like this. Numbers will differ. Process names are
the kernel comm (what `ps -o comm` shows), never the command line.

```json
{
  "capturedAt": "2026-09-18T12:00:00Z",
  "trigger": {
    "source": "dropdiag",
    "kind": "softnet-drop",
    "severity": "critical",
    "subject": "worker-a"
  },
  "node": {
    "name": "worker-a",
    "hostname": "worker-a.lab",
    "kernelRelease": "6.8.0",
    "stale": false,
    "ageSeconds": 2
  },
  "host": {
    "cpuCores": 8,
    "cpuPercent": 640,
    "loadAvg1": 9.1,
    "memoryTotalBytes": 17179869184,
    "memoryUsedBytes": 16000000000
  },
  "cpuHot": true,
  "memoryHot": true,
  "topWorkloadsByCpu": [
    { "namespace": "prod", "pod": "api-7d9f", "cpuPercent": 220, "memoryUsedBytes": 268435456 }
  ],
  "topWorkloadsByMemory": [
    { "namespace": "prod", "pod": "cache-0", "cpuPercent": 12, "memoryUsedBytes": 2147483648 }
  ],
  "topProcessesByCpu": [
    { "pid": 4242, "comm": "iperf3", "cpuPercent": 90, "rssBytes": 4000000 }
  ],
  "policyDropProcesses": [
    { "comm": "nginx", "pid": 88, "pod": "web", "attributionState": "attributed", "packets": 40 }
  ],
  "stack": { "softnetDropped": 1500 },
  "limitations": []
}
```

How to use each block:

- **node.** Which machine. `stale: true` means the agent had already gone
  quiet, so the numbers are the last report, not a fresh sample.
  `ageSeconds` is how old that report was.
- **cpuHot / memoryHot.** CPU is hot when `cpuPercent` is at least 80 times
  the core count. Host CPU is not per-core normalized, so a busy 8-core
  node reads about 800, and the hot line is 640. Memory is hot when used
  memory is at least 90% of total. This is the last agent sample (about 3
  seconds), not a multi-minute baseline.
- **topWorkloadsByCpu / topWorkloadsByMemory.** Kubernetes pods and
  containers, from cgroup v2. This is the usual answer to "which workload"
  on a cluster node. Capped at 10.
- **topProcessesByCpu / topProcessesByMemory.** Host processes: pid, comm,
  CPU percent, RSS. This catches host daemons that are not a pod. Capped
  at 10. No argv, environment, or executable path. CPU percent is 0 on the
  agent's first report after a restart, because there is no previous sample
  yet.
- **policyDropProcesses.** Filled when the drop was an egress TCP policy
  deny that Netra could still match to a socket. Ingress drops and UDP
  stay unattributable. That limit is unchanged.
- **stack, qdiscStats, kernelDrops.** The drop counters already on the
  agent report: softnet, qdisc drops, and kernel drop reason names.

`limitations` on the JSON repeats those bounds so a file read months later
still says what was not collected.

## 5. Prove it with iperf3 and a veth pair

This is the same check GitHub runs as the `auto-capture-veth` job. It does
not need the chart, and it does not attach the node agent's eBPF programs.
It needs Linux, root, Go, `iperf3`, `iproute2`, `curl`, and `python3`.

```bash
sudo ./scripts/ci-auto-capture-veth.sh
```

What you should see:

1. A veth pair. One end stays in the root namespace. The peer moves into
   its own network namespace so the packets are real on the wire. A pair
   in one namespace is short-circuited by the local stack and never shows
   up on AF_PACKET.
2. `iperf3` sending TCP across that pair.
3. A controller with auto-capture on, using the AF_PACKET backend.
4. A synthetic agent report with softnet drops at or above 1000. Real
   softnet counters are too noisy to be the trigger. The report's process
   row is not synthetic: pid and comm are read from the live `iperf3`
   server, with no command line.
5. A PCAP under a temporary directory, then a sibling
   `<id>.context.json`.
6. History for that session with `contextAvailable` true, and a context
   document whose `topProcessesByCpu` names that `iperf3` pid.

Run it again if you want to see a new pid each time. The script deletes
the veth and namespace on exit.

Optional knobs, still without hard-coding a host address:

```bash
sudo CONTROLLER_PORT=31970 CAPTURE_DURATION=12s ./scripts/ci-auto-capture-veth.sh
```

Use a free local port if 30870 is already the installed controller.

## 6. What to do when nothing appears

| What you see | Why |
|---|---|
| No Auto row | Auto-capture is off, or the signal was only a warning |
| Auto row, no PCAP | The capture window closed with no frames. Empty PCAPs are deleted |
| PCAP, no Context | Controller build predates context, or the context file was pruned with an older PCAP |
| Context, `cpuHot` false, CPU looks high | Divide `cpuPercent` by `cpuCores`. Hot means 80% of capacity, not 80 on the raw number |
| Process list empty | The agent has not reported a second sample yet, or this controller build is not receiving `hostProcesses` |
| `policyDropProcesses` empty | The drop was not an attributable egress TCP deny |

Live CPU and memory for the whole cluster, outside an incident, stay on
**Diagnostics → Node Resources**. That page does not list host processes.
The process list exists only inside a drop context file.
