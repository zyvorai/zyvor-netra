# OIDC login, roles, and a locked-down `/metrics`

Netra's API used to have one credential: a shared `NETRA_API_KEY` that could do
everything. This adds **per-person login through your identity provider**, three
**roles**, an audit trail that names the person, and an optional token on
`/metrics`. All of it is off by default and additive: nothing changes until you
set `NETRA_OIDC_ISSUER` or `NETRA_METRICS_TOKEN`, and the static keys keep
working as full admin (your break-glass path).

## How a request is authenticated

The `Authorization: Bearer …` value is checked in this order:

1. `NETRA_API_KEY` — constant-time compare — **admin**.
2. `NETRA_CHATOPS_API_KEY` — **admin** (unchanged; it is a separate trust domain
   from the operator key, but not narrowed by this feature).
3. Anything shaped like a JWT, when OIDC is on — verified against the IdP's
   published keys; its claims decide the role.

Otherwise: **401**. A valid token that maps to no Netra role is **403**, not 401.
If the IdP's keys cannot be fetched and none are cached, the answer is **503**
(transient) rather than 401, so clients do not treat an IdP blip as a logout.
`?token=` in the query string is still accepted for WebSocket-style clients
(as it is for the static key); prefer the header, since URLs get logged.

Agents keep their own `X-Netra-Agent-Key` and are not part of this model.

## Roles

`viewer` < `operator` < `admin`. Each includes everything below it.

| Role       | Can do |
|------------|--------|
| `viewer`   | Read everything, plus read-only computations that happen to POST: policy `plan`/`simulate`/`build`, deny/scope `preview`, intel `preview`, `watchlist/match`. |
| `operator` | Change enforcement rules (deny/allow/CIDR/port/UID/process/DNS/SNI, rate limits, SYN-drop, NetPol rules), baselines, capture control, AI actions. **Also read packet captures** (PCAP download, capture stream) because they contain payloads. |
| `admin`    | Change fleet posture (`ebpf/mode`, `scope`, `shield`, NetPol config), apply/rollback/delete cluster policy and lockdown, GitOps resync/import, toggle features (rewrites deployments), replace the threat-intel feed, and open workload **exec / logs / VNC** consoles. |

The table lives in `internal/api/rbac.go` (`adminOnly`, `operatorGET`,
`viewerPOST`). Anything not listed falls to a safe default by method: a GET needs
viewer, any other method needs operator — so a newly added mutating route is
gated without anyone remembering to. Tests fail the build if a listed route is
renamed or mistyped, or if any mutating route resolves below operator.

Decisions are made on the matched route pattern, in one place, not scattered
across ~200 handlers.

## Configuration

Set on the controller (`netrad`). Bad config **exits at startup**, like the other
security settings; the IdP itself is contacted lazily, so a briefly unreachable
IdP does not stop the controller starting.

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETRA_OIDC_ISSUER` | (off) | Exact `iss` value tokens must carry. Setting it turns OIDC on. Must be `https://`. |
| `NETRA_OIDC_AUDIENCE` | **required** | Value that must appear in the token's `aud`. Required so a token minted for any other app of the same IdP is not accepted here. |
| `NETRA_OIDC_JWKS_URL` | discovered | Override; otherwise read from `<issuer>/.well-known/openid-configuration`, whose `issuer` must equal the configured one. |
| `NETRA_OIDC_ROLES_CLAIM` | `roles` | Claim holding roles/groups. A dotted path walks nested objects (`realm_access.roles`); a claim whose own name contains dots (`https://example.com/roles`) is matched first. |
| `NETRA_OIDC_ROLE_MAP` | literal names | `claimValue=role,…` e.g. `netra-admins=admin,sre=operator,all-staff=viewer`. Empty means the claim values `viewer`/`operator`/`admin` map to themselves. Highest matching role wins. Values are case-sensitive. |
| `NETRA_OIDC_DEFAULT_ROLE` | none | Role for valid tokens that map to nothing. Empty = deny with 403. |
| `NETRA_OIDC_IDENTITY_CLAIM` | `email`, then `sub` | Claim used as the audit identity. |
| `NETRA_OIDC_NAMESPACES_CLAIM` | (off) | Claim holding allowed namespaces (string or array). Empty claim = unrestricted. |
| `NETRA_OIDC_CLUSTERS_CLAIM` | (off) | Claim holding allowed cluster names (match `NETRA_CLUSTER_NAME` / fleet peer names). |
| `NETRA_OIDC_TENANTS_CLAIM` | (off) | Claim holding allowed tenant labels (match `NETRA_CLUSTER_TENANT` / peer `|tenant`). |
| `NETRA_SERVICE_CREDENTIALS_FILE` | (off) | JSON array of scoped service credentials (see below). |
| `NETRA_OIDC_ALLOW_INSECURE_HTTP` | `false` | Permit `http://` issuer/JWKS. Development only. |
| `NETRA_METRICS_TOKEN` | (off) | If set, `GET /metrics` needs `Authorization: Bearer <token>`. |

Helm:

```yaml
auth:
  metricsToken: ""            # or add a "metrics-token" key to auth.existingSecret
  oidc:
    enabled: true
    issuer: https://idp.example.com/realms/netra
    audience: netra
    rolesClaim: realm_access.roles
    roleMap: "netra-admins=admin,sre=operator,all-staff=viewer"
```

`enabled=true` without `issuer` and `audience` fails `helm template`.

### IdP notes

- **Keycloak**: `rolesClaim: realm_access.roles` (or a `groups` mapper). Add an
  audience mapper so `aud` contains your client.
- **Microsoft Entra ID**: app roles arrive in `roles`; set `audience` to the app's
  client ID (v2 tokens) and the issuer to `https://login.microsoftonline.com/<tenant>/v2.0`.
- **Okta / Auth0**: use a custom authorization server / API audience; put groups
  in a claim and point `rolesClaim` at it (Auth0 namespaced claims work as-is).

## What is verified

RS256/384/512, PS256/384/512 and ES256/384/512 only. `none` and every `HS*`
algorithm are rejected (the algorithm-confusion attacks). Signature, `iss`,
`aud`, and `exp` (required) are checked, `nbf` when present, with 60s of clock
skew. RSA keys under 2048 bits and EC points not on the curve are skipped. A JWK
that pins `alg` pins the token's. A token without `kid` is accepted only when the
IdP publishes exactly one key.

Keys are cached for 10 minutes and refetched on rotation (an unknown `kid`), but
never more than once per 15 seconds, so forged key IDs cannot be turned into a
flood against your IdP. A failed refresh keeps serving the last good keys.

## Audit trail

Audit records now name the person: `oidc:ada@example.com`. `X-Netra-Actor` is a
client-supplied header, so it is **ignored for OIDC callers**; a verified
identity always wins. Static-key callers keep the old behaviour (header, else
`api:<ip>`), so existing integrations see no change. `GET /api/v1/whoami` returns
the resolved `kind`, `role` and `identity` for the current credential.

Denials are logged (actor, role, needed role, route) and counted in
`netra_rbac_denied_total`.

## `/metrics`

Open by default, exactly as before. With `NETRA_METRICS_TOKEN` set it needs that
token **or** any valid viewer-or-above credential, sent in the `Authorization`
header — a token in the query string is refused. `/healthz`, `/livez` and
`/readyz` stay open for probes. The OTLP push exporter reads `/metrics` in-process
and sends the token itself, so locking `/metrics` does not break it.

Prometheus scrape config with the token:

```yaml
- job_name: netra
  authorization: {credentials: <token>}
  scheme: https
  static_configs: [{targets: ['netra.netra-system:30870']}]
```

> **Heads-up:** the chart's pod annotations (`prometheus.io/scrape|path`) use
> annotation-based discovery, which cannot send a bearer token. Once you set
> `metricsToken`, scrape with the config above or enable the chart's
> ServiceMonitor (`metrics.serviceMonitor.enabled`), which sends the token from
> the auth Secret automatically (`docs/workload-metrics-slo.md`).

## Using it

Any client that can send a bearer token works, including `netractl` (its
`NETRA_API_KEY` is just the bearer value, so a short-lived JWT works there too).
The **web dashboard's login is still the built-in client-side gate**; there is no
browser redirect flow. To put SSO in front of the UI, run it behind a reverse
proxy such as oauth2-proxy that injects the access token as `Authorization:
Bearer …`.

## Scoped access

Optional namespace, cluster and tenant scopes layer on top of the three roles.
Empty scope lists mean unrestricted (today's default). Scoped callers:

- See only matching namespaces on flow history and related observe queries.
- Are refused (`403`) when they query or mutate outside their scope.
- Cannot use admin-only fleet-wide surfaces (exec/logs/VNC, mode/scope/shield,
  policy apply, feature toggles, intel feed replace) even with an admin role.
- Appear on `GET /api/v1/whoami` with `scoped: true` and the allowed lists.

### Service credentials

`NETRA_SERVICE_CREDENTIALS_FILE` is a JSON array. Each entry has an `id`, a
`role`, optional `namespaces` / `clusters` / `tenants`, and either a plaintext
`key` (bcrypt-hashed at load) or a precomputed `keyHash` (bcrypt hash string):

```json
[
  {
    "id": "payments-reader",
    "key": "replace-me",
    "role": "viewer",
    "namespaces": ["payments"],
    "clusters": ["prod-east"],
    "tenants": ["acme"]
  }
]
```

Present the key as `Authorization: Bearer …` like the static API key. MCP and
automation should use a scoped credential instead of `NETRA_API_KEY` when they
must not see the whole fleet.

## Limits

- No browser authorization-code/PKCE flow, no logout/session store, no token
  revocation beyond expiry — keep token lifetimes short.
- OIDC only (no SAML/LDAP).
- `NETRA_CHATOPS_API_KEY` remains admin-equivalent.
- Roles remain three levels; scopes add namespace/cluster/tenant isolation.

## Verification

Unit and integration: `./scripts/ci-auth-unit.sh` (verifier attacks, the role
table over the real route set, spoof-proof audit actor, the metrics gate, fail-fast
config; runs under `-race`). Live binary: `./scripts/ci-oidc-live.sh` boots the
real `netrad` beside `cmd/netra-ci-idp` (a CI-only fake IdP that must never be
deployed — it mints tokens for anyone) and drives ~40 checks including IdP outage
and recovery. Both run in CI (`go` and `oidc-live` jobs); the chart's OIDC and
metrics-token wiring is covered by the `helm` and `kind-e2e` jobs.

Not yet verified against a real IdP (Keycloak/Entra/Okta); do that once before
relying on it — point a staging controller at the IdP, mint a token, and check
`GET /api/v1/whoami` returns the role you expect.
