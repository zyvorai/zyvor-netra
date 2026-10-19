# Agent ↔ controller mutual TLS

By default an agent proves itself to the controller with one shared key
(`X-Netra-Agent-Key`). Anyone who learns that key can push reports and pull the agent's
configuration. Mutual TLS adds a second factor the key alone cannot satisfy: the agent
must also present a client certificate signed by a CA you control.

**Off by default.** With no setting, nothing about an install changes; the chart renders
byte-for-byte the same manifests.

## What it does and does not do

| | |
|---|---|
| Required for | agent-only requests: `POST /api/v1/agents/report`, the capture stream (`/api/v1/agents/capture/stream`), and the agent-key path of `GET /api/v1/ebpf/config` |
| Not asked of | people: the browser, `netractl`, API keys and OIDC tokens, `/healthz`, `/livez`, `/metrics`. The listener *asks* for a certificate and verifies one only if it is offered, so a browser is never refused for lacking one |
| Still needed | the agent key. A certificate is a second factor, not a replacement; a valid certificate with a wrong key is a 401 |
| Optional | **per-node identity.** With `NETRA_AGENT_MTLS_BIND_NODE=true`, the reported node must match the client certificate identity: URI SAN `spiffe://netra.local/node/<nodeName>` (preferred), else a DNS SAN, else Subject CN. Mismatches return 403 and increment `netra_agent_mtls_node_mismatch_total`. Without bind (default), one shared certificate still proves only "an agent" |

What it does buy: a leaked agent key is no longer enough; the channel cannot be joined by
a network attacker who lacks the certificate; and you can see, per agent, whether it is
using it.

## Modes

`NETRA_AGENT_MTLS` on the controller:

| Mode | Behaviour |
|---|---|
| `off` (default) | never asks for a client certificate |
| `optional` | verifies a certificate when one is offered and records that it was; agents without one are still accepted. The rollout stage |
| `required` | agent-only requests without a verified certificate get `401` |

`NETRA_AGENT_CLIENT_CA` is the PEM bundle the certificates must chain to. It must contain
at least one certificate; netrad **refuses to start** with a typo'd mode, a missing or
empty CA file, or a mode other than `off` over plain HTTP (a client certificate cannot be
requested there, and pretending otherwise would leave you believing agents are
authenticated). If an invalid mode ever reaches the request path anyway it is treated as
`required`, never `off`.

A certificate offered but not accepted (signed by another CA, expired, or lacking the
client-auth key usage) **fails the handshake** in every mode except `off`, in `optional`
too: a wrong certificate is an error, not an anonymous request.

On the agent:

| Variable | Meaning |
|---|---|
| `NETRA_CLIENT_CERT`, `NETRA_CLIENT_KEY` | the agent's certificate and key (both, or neither) |
| `NETRA_CA_FILE` | trust this CA for the controller's certificate (default: system roots) |
| `NETRA_TLS_INSECURE` | unchanged: skip verification of the controller's certificate. The client certificate is still presented |

A configured-but-unusable certificate (missing file, mismatched pair) makes the agent
**refuse to run** with the reason in its error, instead of starting and being rejected on
every report. The same certificate is used for the capture-stream websocket.

## Rolling it out

1. Issue a CA, and a client certificate from it (below). Put `ca.crt`, `tls.crt` and
   `tls.key` in a Secret.
2. `helm upgrade ... --set mtls.mode=optional --set mtls.secretName=netra-agent-mtls`.
   Agents restart with the certificate; the controller verifies it when offered.
3. Watch it: `GET /api/v1/agents` items carry `"mtls": true` for an agent whose latest
   report arrived over a verified certificate (**set by the controller from the
   handshake, never read from the agent's own report**), and `/metrics` has
   `netra_agent_mtls_reports_total`.
4. When every agent shows `mtls: true`: `--set mtls.mode=required`. Anything without a
   certificate now gets `401` (counted in `netra_agent_mtls_rejected_total`; the agent logs
   `config: 401 Unauthorized`).
5. **Per-node certificates (optional):** issue one certificate per node with URI SAN
   `spiffe://netra.local/node/<nodeName>` (cert-manager Certificate per DaemonSet pod
   using downward API `spec.nodeName`). Then `--set mtls.bindNode=true`. Agents that
   present a certificate claiming a different node than the report body get `403`.

Going straight to `required` also works, but agents and controller restart together and the
agents are refused until they have restarted; `optional` first avoids that window.

## Revocation

`NETRA_AGENT_MTLS_DENY_SERIALS` points at a text file of revoked serial numbers
(lowercase hex or decimal, one per line; `#` comments allowed). The controller
re-reads it when the file mtime changes. Prefer short-lived certificates plus
deny-list for emergencies; there is no OCSP. Denied requests return `403` and
increment `netra_agent_mtls_denied_serial_total`.

## Helm

```yaml
mtls:
  mode: optional            # off | optional | required
  bindNode: false           # require cert identity == reported node
  denySerialsSecret: ""     # optional Secret with deny.txt of revoked serials
  secretName: netra-agent-mtls   # a Secret with ca.crt, tls.crt, tls.key
```

or have cert-manager issue and renew the agents' certificate:

```yaml
mtls:
  mode: optional
  certManager:
    enabled: true
    issuerRef: {name: my-ca-issuer, kind: Issuer}
```

The issuer must be a **CA issuer**: cert-manager copies the CA into the Secret's `ca.crt`
for those, and the controller needs it. A self-signed or ACME issuer does not provide one
(the controller would then fail to start with "no PEM certificate", which is the intended
loud failure). Helm cannot check this; `kubectl get secret netra-agent-mtls -o
jsonpath='{.data.ca\.crt}'` shows whether it is there.

The controller mounts **only `ca.crt`** from the Secret, never the agents' private key
(`items:` in the chart; CI asserts it). `tls.enabled` must be true; the chart fails at
template time for a bad mode, `tls.enabled=false`, or no certificate source.

Without cert-manager, a CA and certificate by hand:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=netra-agents" -days 365
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout tls.key -out agent.csr -subj "/CN=netra-agent"
printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' > ext
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out tls.crt -days 90 -extfile ext
kubectl -n netra-system create secret generic netra-agent-mtls \
  --from-file=ca.crt --from-file=tls.crt --from-file=tls.key
```

Keep `ca.key` off the cluster; only the three files above go into the Secret.

## Rotation

- **Agent certificate:** the agent re-reads the certificate and key when their files change
  (a mounted Secret is updated in place, which is what cert-manager does), so the next
  connection uses the renewed pair **without a restart**. While the two files briefly
  disagree mid-rotation the previous pair keeps being used. The smoke test replaces the
  files under a running agent and asserts it keeps reporting.
- **CA:** the controller reads `NETRA_AGENT_CLIENT_CA` at startup. To rotate the CA, put
  both the old and new CA in the bundle, roll the agents onto certificates from the new one,
  then remove the old and restart the controller.

## Verification

- `internal/mtls` tests run real TLS listeners with real certificates: issuer, key usage and
  expiry each fail the handshake; `optional` vs `required`; a chart-default
  (`NETRA_TLS_INSECURE`) agent still presents its certificate; rotation and half-rotation.
- `internal/api` tests put the real handler behind a real TLS listener: key without
  certificate, certificate without key, both, the shared route, the lockout cases
  (`/healthz`, API key), the controller-set `mtls` flag that an agent cannot claim, and an
  invalid mode failing closed.
- `internal/agent` tests check the HTTP client **and** the capture websocket present the
  certificate, and that an unusable one stops `Run`.
- `scripts/ci-mtls-smoke.sh` (CI job `mtls-smoke`) runs the real `netrad`: every unsafe
  setting refused at startup; required mode enforcing certificate, wrong issuer, wrong key
  usage and wrong key. On Linux as root it also runs the real `netra-agent` without a
  certificate (refused, nothing stored), with one (reported, `mtls: true`), and with the
  certificate files replaced under it (keeps reporting).
- Each enforcement point (never asking, request-without-verify, `Allows` always true, the
  shared-route check, trusting the agent's own claim, failing open on a bad mode) and both
  agent wiring points were mutated once; each mutation fails a test.
- The chart step in the `helm` CI job asserts a default render carries none of it, every
  unsafe combination fails, and the controller never mounts the key.
