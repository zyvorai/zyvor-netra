# Microsoft Teams ChatOps (`internal/chatops`)

Optional, off-by-default Microsoft Teams bot integration for `netrad`, sharing all command logic with [Slack ChatOps](chatops.md) (`Dispatch`, `Client`, `pendingAction`) — only inbound request verification, activity parsing, and the confirmation flow differ. Read this alongside `docs/chatops.md`; it isn't repeated in full here.

## Enabling it

Teams bots run on Azure Bot Service, which requires an app registration before Netra ever sees a request:

1. In the Azure Portal, create an **Azure Bot** resource (or reuse an existing multi-tenant app registration). This gives you a **Microsoft App ID** (a GUID) and an app password/secret — Netra's side only ever needs the App ID, never the secret, since it verifies inbound JWTs rather than authenticating outbound Connector API calls in this version.
2. Set the bot's **Messaging endpoint** to `https://<your-netra-host>/chatops/teams`.
3. Add the **Microsoft Teams** channel to the bot resource, and install/sideload the resulting Teams app into the workspace you want it in.
4. Configure `netrad` via environment variables. `helm/netra/values.yaml`'s `chatops:` block wires `NETRA_CHATOPS_TEAMS_APP_ID` alongside the Slack env vars — set `chatops.enabled: true` and `chatops.teamsAppId: "<your app ID>"` (plus `chatops.targetURL`/`chatops.apiKey`, needed by Teams too since they're shared across providers). A Slack signing secret is not required to enable Teams alone.

| Var | Default | Notes |
|---|---|---|
| `NETRA_CHATOPS_TEAMS_APP_ID` | unset | The Azure Bot Service app registration's Microsoft App ID. Unset disables Teams ChatOps entirely — `POST /chatops/teams` isn't even registered. Verified as the inbound JWT's `aud` claim, the same "gates the route" role Slack's `NETRA_CHATOPS_SIGNING_SECRET` plays. |
| `NETRA_CHATOPS_API_KEY` | unset | Same dedicated key Slack ChatOps uses for its own outbound calls back into `netrad`'s `/api/v1/*` — shared across providers, not per-provider, since it's the same trust boundary either way. |
| `NETRA_CHATOPS_TARGET_URL` | `https://127.0.0.1:30870` | Same shared setting as Slack ChatOps. |
| `NETRA_CHATOPS_ALLOW_MUTATIONS` | `false` | Same shared setting as Slack ChatOps — gates `/netra mode ...` for both providers together, not independently. |

## Route wiring

`POST /chatops/teams` is registered outside `s.auth(...)`'s bearer-token middleware — Teams cannot send Netra's own API token — but on the same mux `ha.Gate` wraps, so a standby replica in an HA deployment still correctly returns 503 for it, exactly like `/chatops/slack`.

## Inbound authentication: Bot Framework JWT

Every request Bot Framework relays from Teams carries `Authorization: Bearer <jwt>`. `TeamsVerifier.Verify` (in `teams_signature.go`) checks it end to end:

1. Fetches `https://login.botframework.com/v1/.well-known/openidconfiguration` to discover the current `jwks_uri` (Microsoft's own key-rotation indirection — Netra never hardcodes a key).
2. Fetches and caches that JWKS for 24h, refetching immediately on a key-ID cache miss so a mid-cycle Microsoft key rotation doesn't cause a lockout.
3. Verifies the JWT's RS256 signature against the matching JWKS key (`crypto/rsa.VerifyPKCS1v15` does the actual cryptographic check; this package only parses the JWKS `n`/`e` fields into a `*rsa.PublicKey` and handles JWT framing/JSON — no hand-rolled crypto primitives).
4. Checks `iss == "https://api.botframework.com"` and `aud == NETRA_CHATOPS_TEAMS_APP_ID`.
5. Checks `exp` against the current time — Bot Framework's own short-lived token expiry, rather than a separate replay window like Slack's timestamp check.

A request with a missing, malformed, or failing-any-of-the-above token gets `401` and is never parsed further.

## Activity parsing and @mention stripping

Netra parses the inbound Bot Framework `Activity` JSON body for `type`, `text`, `from.id`, `recipient.id`, and `entities`. Teams wraps an in-message @mention as `<at>Name</at>` inside `text`, with the matching detail in `entities` (`type: "mention"`, `mentioned.id` naming who was mentioned). `stripTeamsMention` removes a mention of the bot itself using that entity data — not by string-matching a display name Netra doesn't know ahead of time — and only falls back to a naive leading-`<at>...</at>` strip when a message carries no mention entities at all (some clients omit them).

## Confirmation flow: a typed second message, not an Adaptive Card button

Slack's confirmation is a single Block Kit button click (`block_actions`), replied to directly in the HTTP response. Teams' equivalent — an Adaptive Card `Action.Submit` — arrives as a separate `invoke` activity requiring its own Connector API reply shape, meaningfully more machinery than "reply in the HTTP response." For v1, Teams instead asks the user to type a second message:

```
Confirm: switch fast-path mode to enforce for 15m (auto-reverts to observe on expiry)?
Reply `/netra confirm <token>` to proceed.
```

`<token>` is `encodePending(...)` — the exact same `method|path|base64(body)|summary` encoding Slack's button `value` uses, reused as-is. When an inbound message starts with `/netra confirm `, the handler decodes the rest as a `pendingAction` and executes it via `Client.Do`, with no server-side pending-action cache here either — same as Slack, the token *is* the state.

## Audit trail

`Client.Do` sets `X-Netra-Actor: chatops-teams:<teams-user-id>` on the confirmed mutation call — mirroring Slack's `chatops:<slack-user-id>` convention exactly, just with a distinct prefix so the two providers stay distinguishable in the audit log (`internal/api`'s existing `actor(r)`/`AddAudit` machinery needs no changes to pick this up).

## Response shape

Bot Framework accepts a synchronous reply as an `Activity` JSON object in the HTTP response body to the incoming webhook, for a simple text turn — the same "reply directly in the HTTP response" simplicity Slack's `writeMessage` uses. No outbound call to the Bot Framework Connector API is made in this version.

## Evidence boundaries

- **No CLI or MCP surface for this feature**, same as Slack ChatOps.
- **`/netra mode` is the only mutating command**, gated by the same `NETRA_CHATOPS_ALLOW_MUTATIONS` flag Slack ChatOps uses (shared, not per-provider).
- **The confirming Teams user (`from.id`) is trusted as-is.** Netra does not maintain its own Teams-tenant membership or role mapping — scope who can invoke `/netra mode` via the Teams app's own installation/permission scope, not Netra.
- **A malformed or expired confirmation token fails closed**, same as Slack.

## Validation

`internal/chatops`'s Teams-specific unit tests cover: JWT verification (valid, wrong audience, wrong issuer, expired, malformed token, malformed header encoding, unsupported `alg`, signature from an unpublished key, unknown key ID, and refetch-on-key-rotation), Activity parsing (mention stripping via entities, a mention of a different recipient left alone, the no-entities fallback, and no-mention text unchanged), the confirm-flow round trip (encode → decode → execute, tagging the actor `chatops-teams:<id>`, and its malformed-token/missing-user failure modes), `ask`'s Ask Netra conversation id staying stable per (`conversation.id`, `from.id`) pair and distinct across users, and the HTTP handler end to end against a mocked JWKS server (`httptest.NewServer` serving a fixed JWKS plus a locally-signed test JWT) — missing/invalid bearer tokens rejected with 401, non-message activities acknowledged with no reply, a slash command replying immediately, and a full mode-change confirm round trip through two HTTP requests. `internal/api`'s route test confirms `/chatops/teams` is entirely absent (404) unless a Microsoft App ID configures the handler, and returns 401 for a request with no bearer token when configured.

**Not yet done**: a live Teams-workspace end-to-end click-through (registering a real Azure Bot Service app against a running `netrad`, installing it into an actual Teams tenant, and clicking/typing through a real slash command and confirmation). Unit tests cover the handler's logic against the documented Bot Framework Activity/JWT shapes using a mocked JWKS server, but nothing in this repository exercises a real Azure/Teams tenant's exact request framing — this mirrors Slack ChatOps's own documented gap in `docs/chatops.md`.
