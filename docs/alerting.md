# Multi-channel alerting

Netra can push anomaly findings to one or more notification channels on an
interval, instead of requiring an operator to poll the dashboard/API.

## Why this exists

`internal/health`, `internal/pathdiag`, `internal/dropdiag`, and related
packages each compute threshold-based anomalies on demand. The controller-side
`internal/alert.Poller` periodically evaluates those sources and publishes
new or escalated findings through `internal/notify`, which fans out to
configured channels (webhook, email, Slack, Microsoft Teams, Twilio SMS /
WhatsApp, and a generic HTTP bridge).

## Mechanism

- A single `internal/alert.Poller` runs on an interval (default 30s).
- Surviving events (after dedup / severity escalation) go through
  `internal/notify.Dispatcher`, which fans each event out to every configured
  channel concurrently with bounded retries and exponential backoff.
- **HA-aware**: only the active leader replica runs a poller.
- **Off by default**: unset channel config disables alerting entirely.

ChatOps (`docs/chatops.md`, `docs/chatops-teams.md`) is a separate **inbound**
path (Slack/Teams call Netra). Do not reuse ChatOps secrets for outbound
alerting.

## Channels

Primary env: `NETRA_ALERT_CHANNELS` (JSON array). Legacy
`NETRA_ALERT_WEBHOOKS` still works when `NETRA_ALERT_CHANNELS` is unset.

```bash
export NETRA_ALERT_CHANNELS='[
  {"type":"webhook","name":"pd","url":"https://hooks.example/pd","secret":"s3cret","minSeverity":"critical"},
  {"type":"email","name":"oncall","smtpHost":"smtp.example:587","from":"netra@example.com","to":["ops@example.com"],"username":"u","password":"p","minSeverity":"warning"},
  {"type":"slack","name":"netops","mode":"incoming","url":"https://hooks.slack.com/services/...","minSeverity":"warning"},
  {"type":"slack","name":"netops-api","mode":"api","token":"xoxb-...","channel":"#netops","minSeverity":"critical"},
  {"type":"teams","name":"ops","url":"https://outlook.office.com/webhook/...","minSeverity":"warning"},
  {"type":"twilio_sms","name":"sms","accountSid":"ACxxx","authToken":"...","from":"+15551234567","to":["+15557654321"],"minSeverity":"critical"},
  {"type":"twilio_whatsapp","name":"wa","accountSid":"ACxxx","authToken":"...","from":"whatsapp:+15551234567","to":["whatsapp:+15557654321"],"minSeverity":"critical"},
  {"type":"httpbridge","name":"bridge","url":"https://bridge.example/notify","secret":"s3cret","channelHint":"sms","minSeverity":"warning"}
]'
```

| `type` | Delivery |
|--------|----------|
| `webhook` | JSON `Event` POST; optional `X-Netra-Signature` HMAC |
| `email` | SMTP (STARTTLS when offered); subject `[Netra][SEVERITY] kind · subject` |
| `slack` | `mode=incoming` (default): Block Kit to Incoming Webhook URL; `mode=api`: `chat.postMessage` with bot token |
| `teams` | Adaptive Card POST to Teams Incoming Webhook URL |
| `twilio_sms` | Twilio Messages API (form POST) |
| `twilio_whatsapp` | Same API; `whatsapp:` prefix applied to From/To when missing |
| `httpbridge` | Envelope `{"channelHint":"...","event":{...}}` for an external bridge; optional HMAC |

Shared optional fields on every channel: `minSeverity` (`info`/`warning`/`critical`,
default `info`), `timeout` (Go duration, default `5s`), `maxAttempts` (default `3`).

### HTTP bridge envelope

```json
{
  "channelHint": "sms",
  "event": {
    "source": "health",
    "kind": "tcp-retransmit",
    "severity": "warning",
    "subject": "payments/checkout → 10.0.4.12:5432",
    "message": "TCP retransmit rate is elevated",
    "timestamp": "2026-09-17T12:00:00Z"
  }
}
```

Use this when you want Netra to stay provider-agnostic and run your own
SMS/WhatsApp/email gateway.

## Poller / queue env

| Env var | Default | Notes |
|---|---|---|
| `NETRA_ALERT_CHANNELS` | unset | JSON channel array; preferred |
| `NETRA_ALERT_WEBHOOKS` | unset | Legacy webhook-only JSON; used only when channels unset |
| `NETRA_ALERT_POLL_INTERVAL` | `30s` | |
| `NETRA_ALERT_COOLDOWN` | `5m` | |
| `NETRA_AGENT_STALE_AFTER` | `45s` | reused agent-staleness knob |
| `NETRA_ALERT_TOPN` | `0` | passed to each source `Build` |
| `NETRA_ALERT_WORKERS` | `2` | dispatcher workers |
| `NETRA_ALERT_QUEUE_SIZE` | `256` | drop-on-full queue |

## Helm

```yaml
alerting:
  enabled: true
  pollInterval: "30s"
  cooldown: "5m"
  workers: 2
  queueSize: 256
  existingSecret: netra-alerting   # key: channels-json
  # or inline (prefer Secret for tokens):
  # channelsJson: '[{"type":"slack",...}]'
  autoCapture:
    enabled: false                 # opt-in; can be true with channels unset
    duration: "60s"
    cooldown: "10m"
    protocol: tcp
    backend: ebpf                  # or afpacket
    maxPps: 1000
    maxConcurrent: 5
    dir: /var/lib/netra/auto-capture
```

## Severity and cooldown

| Situation | Behavior |
|---|---|
| New `(source, kind, subject)` | Fires immediately |
| Repeat, same or lower severity, within cooldown | Suppressed |
| Repeat, same or lower severity, after cooldown | Fires |
| Repeat, higher severity, regardless of cooldown | Fires immediately |

Dedup state is in-memory only and resets on process restart or HA failover.

## Auto-capture

When `NETRA_AUTO_CAPTURE=true`, the same alert poller that feeds notify
channels also starts filtered packet captures on critical drop/congestion
signals and persists PCAPs for later diagnosis. See `docs/capture.md`
(section "Auto-capture on heavy load / packet drops").

| Env | Default | Notes |
|---|---|---|
| `NETRA_AUTO_CAPTURE` | unset (off) | `true` enables |
| `NETRA_AUTO_CAPTURE_DURATION` | `60s` | max 5m |
| `NETRA_AUTO_CAPTURE_COOLDOWN` | `10m` | per-node |
| `NETRA_AUTO_CAPTURE_PROTOCOL` | `tcp` | fallback filter |
| `NETRA_AUTO_CAPTURE_BACKEND` | `ebpf` | or `afpacket` |
| `NETRA_AUTO_CAPTURE_MAX_PPS` | `1000` | |
| `NETRA_AUTO_CAPTURE_MAX_CONCURRENT` | `5` | |
| `NETRA_AUTO_CAPTURE_DIR` | `/var/lib/netra/auto-capture` | PCAP directory |
| `NETRA_AUTO_CAPTURE_MAX_ARTIFACTS` | `50` | prune oldest |
| `NETRA_AUTO_CAPTURE_MAX_TOTAL_MB` | `1024` | |
| `NETRA_AUTO_CAPTURE_MAX_SESSION_MB` | `50` | stop writing beyond this |

Helm: `alerting.autoCapture.*`. Auto-capture can run even when no notify
channels are configured (the poller still evaluates findings). Full trigger
list, artifact download API, and the Linux `scripts/ci-auto-capture-veth.sh`
/ GitHub `auto-capture-veth` smoke live in `docs/capture.md`. Reading the
sibling context JSON: `docs/tutorials/drop-incident-context.md`.

## Not included

- No alert history / ack / silence API or UI.
- No dedup-state persistence across restarts or HA failover.
- Delivery is at-least-once best-effort; a full queue drops events.
- ChatOps credentials are never used for outbound delivery.

## Verification in CI

`scripts/ci-sinks-live.sh` (job `sinks-live`) delivers real alerts from a real controller to loopback
receivers for webhook, Slack, Teams, HTTP bridge and SMTP. One synthetic bad TCP flow produces four
events (the critical `tcp-latency`, the warning `tcp-rto`, their `correlated-degradation`, and the AI
`digest` card); the test asserts each channel gets exactly its severity-filtered set, once each, in its own
format; the webhook and bridge HMAC signatures verify against the body; a channel whose first attempt
fails receives the retry; and no channel secret appears in any delivered body, controller log line or API
response.
