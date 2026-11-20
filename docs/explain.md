# Explain a connection with netractl

`netractl explain` is a passive, read-only diagnostic command over the controller's existing `/api/v1/agents` reports. It works without Cilium or Hubble and can also read a saved report offline. No additional Go dependencies or backend endpoints are introduced.

The dashboard's **Explain** page (nav, next to Connections/Workloads) offers the same scoped diagnostics from the browser against live agent reports — same selectors, same findings, same limitations text, always read-only. It's a straight client-side port (`web/src/lib/explain.ts`, unit-tested against the same edge cases as `cmd/netractl/explain_test.go`) of this exact logic, not a second implementation with its own behavior; the CLI remains the only offline/scripted/`--input file` path. Local Docker-name discovery is also CLI-only, because it requires access to the Docker host socket and cgroup namespaces.

```bash
netractl explain --pod production/payments-api
netractl explain --node worker-1 --pid 1842
netractl explain --node worker-1 --docker payments-api
netractl explain --container EXACT_REPORTED_CONTAINER_ID
netractl explain --destination 192.0.2.10:443
netractl explain --destination '[2001:db8::10]:443'
netractl explain --pod production/payments-api --dns api.example.com
netractl explain --all --format json
netractl ebpf stats > agents.json
netractl explain --input agents.json --pod production/payments-api
cat agents.json | netractl explain --input - --all --format json
```

Live requests reuse `NETRA_URL`, `NETRA_API_KEY`, and the CLI TLS configuration. Certificate verification remains enabled unless the existing `NETRA_TLS_INSECURE=true` opt-in is used. The command refuses HTTP redirects and limits report input to 32 MiB. It does not print backend error bodies.

## What the result means

- `observed-block`: a sampled event reports a block, with its reason and hook. The event does not prove which historical rule ID caused it.
- `network-event`: a sampled event matching the scope. An `observed` outcome does not prove delivery to the application.
- `tcp-established`: active or passive TCP establishment counters are nonzero. This is historical counter evidence, not a current health check.
- `tcp-loss-signal`: retransmission or retransmission-timeout counters are nonzero. They do not by themselves prove a firewall drop or failed initial connection.
- `icmp-pmtu`, `icmp-unreachable`, `icmp-time-exceeded`, `icmp-parameter-problem`: node/interface-scoped TC error observations and next checks. These appear only for node-wide or `--all` scope; see [ICMP diagnostics](icmp-diagnostics.md).
- `dns-response`, `dns-response-error`: matched native UDP/53 response code, resolver, query, and code-specific next check; see [DNS response diagnostics](dns-response-diagnostics.md).
- `dns-counters`: observed query, matched-response, and failure counters. Unmatched queries must not be interpreted as confirmed timeouts.
- `bpf-maps-missing`: an agent's BPF object is missing one or more expected pinned maps — allow/rate/ICMP controls fail open until the agent image is rebuilt and rolled. Node-wide or `--all` scope only.
- `rate-drop`: a destination's PPS ceiling has cumulative dropped packets since the map was created. Available at node-wide/`--all` scope and, unlike ICMP/`bpf-maps-missing`, also when scoped with `--destination`.

Each finding includes a next investigation step. Text output escapes dynamic metadata before displaying it in the terminal; JSON output uses schema version 1 and preserves typed fields. `evidence-found` only means there are matching findings, not that the connection is healthy or unhealthy. Successful diagnosis returns exit code 0 even when no evidence matches; argument, input, and transport errors return 1. Consumers should inspect the report fields.

## Exact scope and evidence boundaries

Selectors combine with AND. Pod scope requires `namespace/name` or `--namespace`. PID scope requires `--node`, because PIDs repeat across hosts. Event PIDs can refer to an earlier process incarnation; TCP rows with stale ownership are excluded from PID queries. `--container` requires an exact reported container ID. For local Docker names, use the separate `--docker` discovery path below.

`--destination` accepts a literal IP, optionally with a port, and compares packet destinations for events or remote peers for TCP counters. It performs no DNS lookup. `--dns` matches a normalized observed query name and may be combined with node/namespace/pod scope. It cannot be combined with PID, container, or destination scope: the existing DNS counters lack those identities, and DNS-to-IP/TCP correlation is not available.

`bpf-maps-missing` and `rate-drop` are node-level agent-health signals, not workload-scoped evidence: they appear only under node-wide/`--all` scope (any namespace/pod/PID/container/`--dns` selector excludes them), except `rate-drop`, which additionally matches `--destination` since a rate-drop row already identifies a destination IP.

Freshness uses each agent's `observedAt` plus its `stale` flag. Reports are excluded if they are marked stale, lack node/time, exceed `--max-age` (default 2m, maximum 24h), or are more than one minute in the future. For a saved report, choose a larger age bound explicitly when needed. Event timestamps may be older than the report timestamp and are displayed as reported. TCP/DNS counters are cumulative, not restricted to a time window.

`--limit` bounds displayed findings (default 50, maximum 1000). The result still counts all matching findings and reports truncation. Narrow selectors for a more useful result. Empty evidence is never labeled healthy. Reports can contain workload identities, IPs, DNS names, and process names; review them before sharing.

## Validation and scope

The new tests exercise invalid arguments, exact scope, IPv6 and mapped IPv4, PID/node isolation, stale socket ownership, freshness, bounded input/output, HTTP authentication and errors, terminal escaping, JSON, and the offline CLI. Existing `go test ./...` CI discovers the tests automatically.

This release implements the first proposed adoption feature: passive one-command diagnostics. Active probes, AI-agent enforcement profiles, sanitized report sharing, and deployment comparisons are separate follow-up features.


## Local Docker-name discovery

```bash
netractl explain --node worker-1 --docker payments-api
netractl explain --node worker-1 --docker payments-api --dns api.example.com
netractl explain --node worker-1 --docker payments-api --docker-socket /run/user/1000/docker.sock
```

Run on the Linux Docker host with access to its Unix socket, host PID namespace,
and cgroup-v2 mount. The default socket is `/var/run/docker.sock`; remote TCP
Docker daemons, abbreviated IDs, cgroup v1, and Docker Desktop host discovery
are unsupported. `DOCKER_HOST` is not consulted. The explicitly supplied Netra
node must correspond to this host; the command cannot prove that mapping.

The command inspects the exact running name or full 64-character ID, resolves the
init process's cgroup inode, fetches Netra reports, and rechecks the full container
ID, PID, start time, and cgroup. A restart or cgroup migration aborts diagnosis.
Reports preceding the container start are excluded. Findings match the cgroup ID,
not a potentially reused PID. Nested child cgroups are outside this scope, and
retained counters do not prove an exact container-incarnation measurement window.

Docker discovery supports destination or DNS filters, but cannot combine with
`--all`, `--input`, PID, namespace/pod, or `--container`. DNS rows can be scoped
here because their reported cgroup ID is available. JSON includes inspected
identity with the cgroup ID encoded as a decimal string to preserve 64-bit precision.

Only selected Docker identity fields are decoded for output. Raw inspect responses
and server error bodies are never printed, and the Netra bearer token is never
sent to Docker. Socket requests are read-only, bounded to 4 MiB, time-limited,
and reject redirects. Accessing the Docker socket still requires the host's
existing permissions; the command does not alter them.
