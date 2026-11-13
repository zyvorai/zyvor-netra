---
sidebar_position: 4
---

# How Netra is tested

Every use case Netra ships has a job in GitHub Actions that runs it for real: a real controller,
and where the use case needs it a real agent on a real kernel, a real Kubernetes cluster, or a real
browser. Each job is a script in the repository (`scripts/ci-*.sh`) that exits non-zero on the first
failed assertion, so the same command runs on your machine. Each was checked by breaking the thing it
tests and watching the job fail.

| Use case | What CI does |
|---|---|
| Enforcement | A real agent on a veth: deny, allow, CIDR and port rules drop exactly what they name in enforce mode and never in observe (IPv4 and IPv6); an allow rule beats a deny rule; a lease expires on its own; the agent fails open to observe when the controller dies |
| Packet capture | Both backends stream to a `.pcap` that `tcpdump` reads: filter, both directions, stop, history |
| Kernel sensors | Real verifier and real traffic on x86_64 and arm64, and on a 6.8 kernel nightly |
| Install and upgrade | The previous release installs and takes state; `helm upgrade` to the new one keeps the state and API key and starts the agent; a pod restart and a `helm rollback` keep the state readable |
| Plain manifests | `kubectl apply -k deploy/` on a real cluster |
| High availability | Two replicas: one leader, the standby refuses the API, crash and graceful failover with shared state |
| State | Rules, audit and baseline survive `kill -9`; an enforcement lease is never resurrected; a corrupt state file is refused and left untouched |
| Exports and alerts | Webhook, Slack, Teams, HTTP bridge, SMTP, OTLP and syslog delivered to real receivers, with signatures, retries, the severity filter, and no secret in any body, log line or response |
| Access control | OIDC and roles against a live controller; mutual TLS with a real agent, including certificate renewal under a running agent |
| MCP and CLI | The MCP server over stdio against a live controller; every `netractl` command, including the mutating ones |
| Web UI | A real browser signs in and out, loads every page in `web/src/lib/investigation.ts` against a real controller, sees seeded data, and adds a deny rule and a lease through the Firewall page |

Nightly, the whole suite also runs under the race detector, the parsers are fuzzed, the privileged suites
run on each runner image, and images are built for both architectures. Dependency updates and known
vulnerabilities are checked on every change.

Two things are honestly not covered: a real Cilium/Hubble install (the chart's Cilium mode is checked
by rendering only), and cross-node shared storage for HA (the HA test runs on one node, so it proves the
election and the state lock, not your RWX filesystem).

The job-by-job map, with how to run each locally, is `docs/ci.md` in the repository.
