# ChatOps (`internal/chatops`)

Optional, off-by-default ChatOps integration for `netrad`, supporting both Slack (slash commands + interactive buttons) and Microsoft Teams (bot messages). Read commands (`status`, `health`, `audit`, `ask`) reply immediately; the one mutating command (`mode`) always requires a second confirmation step before it executes anything, mirroring the web UI's own `confirm()` dialogs. See below for Slack; Teams is documented in [`docs/chatops-teams.md`](chatops-teams.md).

## Why two separate providers, one shared core

Slack signs inbound requests with an HMAC over the raw request body; Microsoft Teams authenticates with bot-framework JWTs — different enough shapes that forcing both behind one `Verify` interface from day one risked a poor abstraction. Each provider gets its own inbound verification and HTTP handler (`signature.go`/`handler.go` for Slack, `teams_signature.go`/`teams_handler.go` for Teams), but both call the exact same `Dispatch`/`Client`/`pendingAction` command logic in `commands.go` and `client.go` — nothing about the actual commands is duplicated between providers.

## Enabling it

Create a Slack app (from-scratch or an app manifest), enable **Slash Commands** (`/netra`, request URL `https://<your-netra-host>/chatops/slack`) and **Interactivity & Shortcuts** (same request URL), then:

```bash
helm upgrade --install netra ./helm/netra --reuse-values \
  --set chatops.enabled=true \
  --set chatops.allowMutations=true \
  --set chatops.existingSecret=my-chatops-secret   # keys: signing-secret, api-key
```

Or directly via environment variables on `netrad`:

| Var | Default | Notes |
|---|---|---|
| `NETRA_CHATOPS_SIGNING_SECRET` | unset | Slack app's own signing secret (**Basic Information → Signing Secret** in the Slack app config). Unset disables ChatOps entirely — `POST /chatops/slack` isn't even registered. |
| `NETRA_CHATOPS_API_KEY` | unset | Dedicated bearer credential ChatOps uses to call back into `netrad`'s own `/api/v1/*` — a separate trust domain from `NETRA_API_KEY`, matching the existing `NETRA_AGENT_KEY` separate-key convention, so a leaked Slack app credential can't be replayed as full operator API access. |
| `NETRA_CHATOPS_TARGET_URL` | `https://127.0.0.1:30870` | Where ChatOps sends its own outbound API calls — normally the controller's own in-cluster service address. |
| `NETRA_CHATOPS_ALLOW_MUTATIONS` | `false` | Gates which commands are even *registered* in the dispatch table at startup, not just whether they execute — mirrors `cmd/netra-mcp/main.go`'s `buildServer(c, allowMutations)` exactly. With this unset, `/netra mode ...` isn't a recognized command at all. |

## Route wiring

`POST /chatops/slack` is registered outside `s.auth(...)`'s bearer-token middleware — Slack cannot send Netra's own API token — but on the same mux `ha.Gate` wraps, so a standby replica in an HA deployment still correctly returns 503 for it with no extra wiring. The route's actual authentication is `VerifySlackSignature`: an HMAC-SHA256 over `v0:<timestamp>:<raw body>` using the Slack signing secret, with a 5-minute replay window on `X-Slack-Request-Timestamp`. A request with a bad or stale signature gets `401`, is never parsed further, and never reaches the controller call-through.

## Commands

| Command | Effect |
|---|---|
| `/netra help` | Lists available commands (adjusted to whether mutations are enabled). |
| `/netra status` | Controller status — read-only, calls `GET /api/v1/status`. |
| `/netra health` | Top 5 network-health anomalies — `GET /api/v1/ebpf/health?limit=5`. |
| `/netra audit` | 5 most recent audit events — `GET /api/v1/audit?limit=5`. |
| `/netra ask <question>` | Ask Netra's AI layer about cluster health — same in-process graph (`POST /api/v1/ai/agent`) as the web "Ask Netra" card, heuristic-only unless `NETRA_AI_API_KEY` is set. Read-only, no confirmation. An empty question (`/netra ask` with no text) still replies with a general cluster brief. Remembers the last few turns per channel per user — see "Conversation memory" below. A deny/rate/allow sentence may include a preview-only draft. |
| `/netra forget` | Clear this channel's Ask Netra conversation memory and start fresh. Read-only, no confirmation. |
| `/netra mode observe` | Switch the fast-path to observe mode. **Requires confirmation.** |
| `/netra mode enforce [lease]` | Switch to enforce mode for `lease` (default `15m`, auto-reverts to observe on expiry). **Requires confirmation.** |
| `/netra capture start NODE [protocol=tcp host=IP port=N duration=60s]` | Start a packet-capture session on one node; at least one of `protocol=`/`host=`/`port=` is required. Captures full packet bytes by default. **Requires confirmation.** |
| `/netra capture stop NODE` | Stop an active capture before its duration expires. **Requires confirmation.** |

Read commands (`status`/`health`/`audit`) reply with a compact, indented-JSON summary of the underlying API response (capped well under Slack's per-block size limit) rather than a hand-parsed field-by-field rendering, so replies stay correct as those endpoints' response shapes evolve — they are not reformatted into custom prose. `/netra ask` is the one exception: it renders the AI brief's headline/severity/summary/findings/next-steps as formatted chat text, matching the web card's presentation rather than a JSON dump.

## Conversation memory

`/netra ask` remembers the last few turns of a conversation — see
[`docs/ai.md`](ai.md#conversation-memory) for the full scope, bounds, and
what's stored. For ChatOps specifically: the conversation key is computed
automatically, never typed by the operator — `slack:<channel_id>:<user_id>`
for Slack, `teams:<conversation.id>:<from.id>` for Teams — so the same
person asking follow-up questions in the same channel gets a continuous
thread with no setup, and a different user in the same channel gets their
own, separate one. `/netra forget` clears it (via `POST /api/v1/ai/forget`)
without waiting out the 30-minute idle timeout.

## The confirmation flow is stateless by design

`/netra mode ...` never calls the controller on the initial slash command. It replies with a Block Kit confirmation message containing one button; the entire pending mutation — HTTP method, path, base64-encoded body, and a human summary — is encoded directly into that button's own `value` field (`method|path|base64(body)|summary`). Slack round-trips that value back verbatim on the button click (a `block_actions` interaction, same request URL), and the handler decodes it and executes it right there. There is no server-side pending-action cache anywhere in `internal/chatops` or `internal/store` — the button *is* the state. This keeps ChatOps fully self-contained: it needs no coordination with the store beyond the one outbound API call it makes to execute a confirmed action.

The `enforce` mode gets Slack's "danger" button style as a visual cue; every other mutating confirmation uses the plain "primary" style.

## Audit trail

`Client.Do` sets `X-Netra-Actor: chatops:<slack-user-id>` on the confirmed mutation call. The existing `actor(r)`/`AddAudit` machinery in `internal/api` picks this up with no new audit code — a confirmed `/netra mode enforce` shows up in the same Audit page and history as any other operator action, attributed to the Slack user who clicked Confirm, not to whoever ran the original slash command (they may differ; Netra trusts whichever Slack user ID is on the interaction payload that actually triggers the call).

## Evidence boundaries

- **No CLI or MCP surface for this feature.** ChatOps is an inbound integration (Slack calls Netra), not something `netractl` or an MCP client calls — there is nothing here for either of those to wrap.
- **`/netra mode` is the only mutating command in v1.** Read commands (`status`/`health`/`audit`/`ask`/`forget`) never require confirmation and never produce an audit event, matching how the equivalent read-only API endpoints behave everywhere else in Netra.
- **The confirming Slack user is trusted as-is.** Netra does not maintain its own Slack-workspace membership or role mapping — anyone who can click a button in the channel the slash command was run in can confirm it. Scope who can *invoke* `/netra mode` via Slack's own app/channel permissions, not Netra.
- **A malformed or expired confirmation value fails closed**, replying "this confirmation has expired or is malformed; re-run the slash command" rather than guessing at intent.

## Validation

`internal/chatops`'s Slack/shared-dispatch unit tests (29 total — Teams-specific coverage is listed separately in `docs/chatops-teams.md`) cover: HMAC signature verification (valid, wrong secret, tampered body, expired/future timestamp outside the replay window, missing secret, malformed timestamp), command dispatch (help, status call-through with the right auth header, unknown command, `mode` disabled without `allowMutations`, `mode` never calling the controller before confirmation, invalid mode rejection, `ask`/`forget` call-through and their conversation-memory `conversationId` pass-through), the pending-action encode/decode round trip and its rejection of malformed input, and the HTTP handler end to end (bad signature → 401, slash command replies, confirmation blocks returned instead of immediate execution, a confirmed interaction executing and correctly tagging the actor, an unrecognized interaction, `NewHandler` panicking without a signing secret, and `ask`'s conversation id staying stable per channel+user and distinct across users). `internal/api`'s route test confirms `/chatops/slack` is entirely absent (404) unless a signing secret configures the handler, and returns 401 from `VerifySlackSignature` — not from the bearer-token check every other route uses — when configured but unsigned.

**Not yet done**: a live Slack workspace end-to-end check (registering a real Slack app against a running `netrad` and clicking through an actual slash command and confirmation). Unit tests cover the handler's logic against the documented Slack request/payload shapes, but nothing in this repository exercises a real Slack app's exact request framing.

For the Teams provider's validation status, see [`docs/chatops-teams.md`](chatops-teams.md#validation).
