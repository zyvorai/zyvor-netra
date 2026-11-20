#!/usr/bin/env bash
# Netra — outbound alert and export sinks, delivered for real (any OS, no root)
#
# Real `netrad` pushing to real (loopback) receivers written for this test: webhook,
# Slack, Teams, HTTP bridge, SMTP, OTLP/HTTP and syslog (UDP and TCP). One synthetic
# agent report makes the controller's own detectors raise two findings (a critical
# TCP-latency one and a warning RTO one), and one deny rule makes an audit event.
# Asserts what an operator relies on:
#
#   delivery   every configured channel receives the finding in its own format, once
#              (the poller's cooldown de-duplicates); a channel below the finding's
#              severity receives nothing; a channel that fails its first attempt is
#              retried and receives it exactly once more
#   integrity  the webhook and bridge HMAC signatures verify against the body
#   export     OTLP metrics, logs and traces arrive with the configured auth header;
#              audit events arrive as RFC 5424 over UDP and over TCP
#   secrets    no channel secret, SMTP password or OTLP token appears in any request
#              body, any controller log line, or any API response
#
# Usage:
#   ./scripts/ci-sinks-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

D="$(mktemp -d "${TMPDIR:-/tmp}/netra-sinks.XXXXXX")"
PORT="${CONTROLLER_PORT:-18092}"
HTTP_PORT="${RECEIVER_HTTP_PORT:-18192}"
SMTP_PORT="${RECEIVER_SMTP_PORT:-18292}"
SYSLOG_PORT="${RECEIVER_SYSLOG_PORT:-18392}"
API_KEY="ci-sinks-api-key"
AGENT_KEY="ci-sinks-agent-key"
HOOK_SECRET="whsec-SECRET-hook-1f3a"
BRIDGE_SECRET="brsec-SECRET-bridge-9c2d"
OTLP_TOKEN="otlp-SECRET-token-7b6e"
BASE="http://127.0.0.1:${PORT}"
command -v python3 >/dev/null || { echo "missing required command: python3" >&2; exit 1; }

PIDS=()
cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  for p in "${PIDS[@]}"; do
    for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
  done
  [[ "${KEEP:-}" == 1 ]] || rm -rf "$D"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; [[ -f "$D/netrad.log" ]] && tail -n 12 "$D/netrad.log" >&2; exit 1; }

echo "==> build netrad"
CGO_ENABLED=0 go build -trimpath -o "$D/netrad" ./cmd/netrad

cat >"$D/receiver.py" <<'PY'
"""Loopback receivers. Everything received is appended to received.jsonl."""
import json, os, socket, socketserver, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT = sys.argv[1]
HTTP_PORT, SMTP_PORT, SYSLOG_PORT = (int(x) for x in sys.argv[2:5])
lock = threading.Lock()
flaky_calls = {"n": 0}

def rec(kind, **kw):
    with lock, open(OUT, "a") as f:
        f.write(json.dumps({"kind": kind, "t": time.time(), **kw}) + "\n")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        rec("http", path=self.path, headers={k.lower(): v for k, v in self.headers.items()}, body=body.decode("utf-8", "replace"))
        if self.path == "/flaky":
            with lock:
                flaky_calls["n"] += 1
                first = flaky_calls["n"] == 1
            if first:               # fail the first attempt, accept the retry
                self.send_response(500); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")

class SMTP(socketserver.StreamRequestHandler):
    def w(self, s): self.wfile.write((s + "\r\n").encode()); self.wfile.flush()
    def handle(self):
        self.w("220 fake ESMTP"); frm, to, data = "", [], None
        while True:
            line = self.rfile.readline()
            if not line: return
            cmd = line.decode("utf-8", "replace").strip()
            up = cmd.upper()
            if up.startswith("EHLO") or up.startswith("HELO"): self.w("250 fake")      # no STARTTLS, no AUTH
            elif up.startswith("MAIL FROM"): frm = cmd; self.w("250 ok")
            elif up.startswith("RCPT TO"): to.append(cmd); self.w("250 ok")
            elif up == "DATA":
                self.w("354 go")
                buf = b""
                while not buf.endswith(b"\r\n.\r\n"):
                    chunk = self.rfile.readline()
                    if not chunk: return
                    buf += chunk
                rec("smtp", mail_from=frm, rcpt=to, data=buf.decode("utf-8", "replace")); self.w("250 queued")
            elif up == "QUIT": self.w("221 bye"); return
            else: self.w("250 ok")

class SyslogTCP(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            rec("syslog-tcp", line=line.decode("utf-8", "replace").rstrip("\r\n"))

class Quiet(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", SYSLOG_PORT))
    while True:
        data, _ = s.recvfrom(65535); rec("syslog-udp", line=data.decode("utf-8", "replace").rstrip("\r\n"))

ThreadingHTTPServer.daemon_threads = True
servers = [ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), H), Quiet(("127.0.0.1", SMTP_PORT), SMTP), Quiet(("127.0.0.1", SYSLOG_PORT), SyslogTCP)]
for s in servers: threading.Thread(target=s.serve_forever, daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
PY

: >"$D/received.jsonl"
python3 "$D/receiver.py" "$D/received.jsonl" "$HTTP_PORT" "$SMTP_PORT" "$SYSLOG_PORT" >"$D/receiver.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do grep -q ready "$D/receiver.log" 2>/dev/null && break; sleep 0.25; done
grep -q ready "$D/receiver.log" || { cat "$D/receiver.log" >&2; fail "the receivers did not start"; }

CHANNELS="$(python3 - <<PY
import json
h = "http://127.0.0.1:${HTTP_PORT}"
print(json.dumps([
  {"type": "webhook", "name": "hook", "url": h + "/hook", "secret": "${HOOK_SECRET}", "minSeverity": "info"},
  {"type": "webhook", "name": "crit", "url": h + "/crit", "minSeverity": "critical"},
  {"type": "webhook", "name": "flaky", "url": h + "/flaky", "minSeverity": "critical", "maxAttempts": 3},
  {"type": "slack", "name": "slack", "mode": "incoming", "url": h + "/slack", "minSeverity": "critical"},
  {"type": "teams", "name": "teams", "url": h + "/teams", "minSeverity": "critical"},
  {"type": "httpbridge", "name": "bridge", "url": h + "/bridge", "secret": "${BRIDGE_SECRET}", "channelHint": "sms", "minSeverity": "critical"},
  {"type": "email", "name": "mail", "smtpHost": "127.0.0.1:${SMTP_PORT}", "from": "netra@ci.example", "to": ["ops@ci.example"], "minSeverity": "critical"},
]))
PY
)"

start_netrad() { # start_netrad <env...>: run in the background; exec so $! is netrad itself
  exec env NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY="$API_KEY" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_LISTEN=":${PORT}" "$@" "$D/netrad" >>"$D/netrad.log" 2>&1
}
wait_ready() {
  for _ in $(seq 1 60); do
    curl -sf -H "Authorization: Bearer ${API_KEY}" "${BASE}/api/v1/status" >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  fail "netrad never became ready"
}
api() { curl -sf -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' "$@"; }

echo "==> start netrad with every sink configured"
start_netrad \
  NETRA_ALERT_CHANNELS="$CHANNELS" NETRA_ALERT_POLL_INTERVAL=2s \
  NETRA_OTLP_ENDPOINT="http://127.0.0.1:${HTTP_PORT}/otlp" NETRA_OTLP_HEADERS="Authorization=Bearer ${OTLP_TOKEN}" NETRA_OTLP_INTERVAL=2s \
  NETRA_SYSLOG_ADDR="127.0.0.1:${SYSLOG_PORT}" NETRA_SYSLOG_NETWORK=udp NETRA_SYSLOG_INTERVAL=2s &
NETRAD=$!
PIDS+=("$NETRAD")
wait_ready

echo "==> one synthetic agent report raises a critical and a warning finding and carries a blocked packet; one deny rule makes an audit event"
NOW="$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
report="{\"node\":\"sink-ci\",\"observedAt\":\"${NOW}\",\"tcpHealth\":[{\"comm\":\"curl\",\"family\":\"ipv4\",\"remoteIp\":\"203.0.113.9\",\"remotePort\":443,\"srttUs\":900000,\"rtos\":1}],\"events\":[{\"timestampNs\":1,\"observedAt\":\"${NOW}\",\"direction\":\"egress\",\"family\":\"ipv4\",\"sourceIp\":\"10.0.0.7\",\"destinationIp\":\"203.0.113.5\",\"sourcePort\":40000,\"destinationPort\":443,\"protocol\":\"TCP\",\"action\":\"drop\",\"reason\":\"deny_ip\"}]}"
curl -sf -X POST -H "X-Netra-Agent-Key: ${AGENT_KEY}" -H 'Content-Type: application/json' -d "$report" "${BASE}/api/v1/agents/report" >/dev/null
api -X POST -d '{"ip":"203.0.113.5","direction":"egress"}' "${BASE}/api/v1/ebpf/deny" >/dev/null

# Keep the report fresh so the finding stays current for the whole test.
( for _ in $(seq 1 60); do
    n="$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
    curl -sf -X POST -H "X-Netra-Agent-Key: ${AGENT_KEY}" -H 'Content-Type: application/json' -d "${report//$NOW/$n}" "${BASE}/api/v1/agents/report" >/dev/null 2>&1 || true
    sleep 2
  done ) &
PIDS+=($!)

count() { python3 - "$D/received.jsonl" "$@" <<'PY'
import json, sys
path, kind = sys.argv[1], sys.argv[2]
sel = sys.argv[3] if len(sys.argv) > 3 else ""
n = 0
for l in open(path):
    r = json.loads(l)
    if r["kind"] == kind and (not sel or r.get("path") == sel):
        n += 1
print(n)
PY
}
await() { # await <description> <kind> <path> <min>
  for _ in $(seq 1 60); do
    [[ "$(count "$2" "$3")" -ge "$4" ]] && return 0
    sleep 0.5
  done
  echo "--- received so far:" >&2; cut -c1-160 "$D/received.jsonl" >&2
  fail "$1 never arrived"
}

echo "==> wait for every channel"
await "the webhook (info) findings" http /hook 4
for p in /crit /slack /teams /bridge; do await "the ${p#/} channel" http "$p" 3; done
await "the flaky channel and its retry" http /flaky 4
await "the e-mails" smtp "" 3
await "the OTLP metrics" http /otlp/v1/metrics 1
await "the OTLP logs" http /otlp/v1/logs 1
await "the OTLP traces" http /otlp/v1/traces 1
await "the UDP syslog line" syslog-udp "" 1

echo "==> let two more poll cycles pass: nothing is delivered twice"
sleep 6

RESULT_JSON="$(python3 - "$D/received.jsonl" "$HOOK_SECRET" "$BRIDGE_SECRET" "$OTLP_TOKEN" <<'PY'
import hashlib, hmac, json, re, sys
path, hook_secret, bridge_secret, otlp_token = sys.argv[1:5]
rs = [json.loads(l) for l in open(path)]
def at(p): return [r for r in rs if r["kind"] == "http" and r["path"] == p]
def events(p): return [json.loads(r["body"]) for r in at(p)]
problems = []
def need(cond, msg):
    if not cond: problems.append(msg)

# What one bad TCP flow really produces: the two raw findings, their correlation, and
# the AI digest card that summarises them (one each; the poller's cooldown stops repeats).
ALL = [("correlated-degradation", "critical"), ("digest", "critical"), ("tcp-latency", "critical"), ("tcp-rto", "warning")]
CRIT = [k for k in ALL if k[1] == "critical"]
def kinds(evs): return sorted((e["kind"], e["severity"]) for e in evs)

# webhook, minSeverity info: everything, once each, with a valid signature
hook = at("/hook")
need(kinds(events("/hook")) == ALL, f"hook received {kinds(events('/hook'))}, want exactly {ALL}")
for r in hook:
    want = "sha256=" + hmac.new(hook_secret.encode(), r["body"].encode(), hashlib.sha256).hexdigest()
    need(r["headers"].get("x-netra-signature") == want, "the webhook signature does not verify against the body")
    need(r["headers"].get("content-type") == "application/json", "webhook content-type")
    e = json.loads(r["body"])
    if e["kind"] != "digest":
        need("203.0.113.9" in json.dumps(e) or e.get("subject") == "curl", f"the event does not identify its subject: {e}")
    need(e.get("timestamp"), "an event without a timestamp")

# minSeverity critical: the critical findings only, never the warning
crit = events("/crit")
need(kinds(crit) == CRIT, f"a critical-only channel received {kinds(crit)}, want {CRIT}")
need("x-netra-signature" not in at("/crit")[0]["headers"], "a channel without a secret must not sign")

# a channel whose first attempt fails is retried: every event once, the first one twice
flaky = at("/flaky")
need(len(flaky) == len(CRIT) + 1, f"flaky channel saw {len(flaky)} requests, want {len(CRIT)} events plus one retry")
from collections import Counter
bodies = Counter(r["body"] for r in flaky)
first = flaky[0]["body"] if flaky else None
need(bodies.get(first) == 2 and sorted(bodies.values()) == [1] * (len(CRIT) - 1) + [2], f"want the failed event sent twice and every other event once, got counts {sorted(bodies.values())}")

# slack, teams, bridge, e-mail: each in its own format, one message per critical finding
slack = events("/slack"); need(len(slack) == len(CRIT), f"slack got {len(slack)}, want {len(CRIT)}")
need("tcp-latency" in json.dumps(slack), "slack bodies do not mention the finding")
teams = events("/teams"); need(len(teams) == len(CRIT), f"teams got {len(teams)}, want {len(CRIT)}")
need(all(t.get("type") == "message" and t.get("attachments") for t in teams), f"a teams body is not an adaptive-card message: {json.dumps(teams)[:160]}")
bridge = at("/bridge"); need(len(bridge) == len(CRIT), f"bridge got {len(bridge)}, want {len(CRIT)}")
envs = [json.loads(r["body"]) for r in bridge]
need(all(e.get("channelHint") == "sms" for e in envs), "a bridge envelope lost its channelHint")
need(kinds([e["event"] for e in envs]) == CRIT, f"bridge events {kinds([e['event'] for e in envs])}")
for r in bridge:
    want = "sha256=" + hmac.new(bridge_secret.encode(), r["body"].encode(), hashlib.sha256).hexdigest()
    need(r["headers"].get("x-netra-signature") == want, "a bridge signature does not verify")
mail = [r for r in rs if r["kind"] == "smtp"]; need(len(mail) == len(CRIT), f"smtp got {len(mail)} messages, want {len(CRIT)}")
for m in mail:
    need("ops@ci.example" in json.dumps(m["rcpt"]) and "netra@ci.example" in m["mail_from"], f"smtp envelope {m['mail_from']} {m['rcpt']}")
    need(re.search(r"^Subject: \[Netra\]\[CRITICAL\] ", m["data"], re.M) is not None, f"unexpected e-mail subject:\n{m['data'][:160]}")
need(any("tcp-latency" in m["data"] for m in mail), "no e-mail names the tcp-latency finding")

# OTLP: all three signals, the configured auth header, valid JSON of the right shape
for sig, top in (("metrics", "resourceMetrics"), ("logs", "resourceLogs"), ("traces", "resourceSpans")):
    got = at(f"/otlp/v1/{sig}")
    need(got, f"no OTLP {sig}")
    for r in got[:1]:
        need(r["headers"].get("authorization") == f"Bearer {otlp_token}", f"OTLP {sig}: the configured auth header was not sent")
        need(r["headers"].get("content-type", "").startswith("application/json"), f"OTLP {sig}: content-type")
        try:
            need(top in json.loads(r["body"]), f"OTLP {sig}: body has no {top}")
            if sig == "traces":
                need("203.0.113.5" in r["body"], "the OTLP span for the blocked packet does not carry its destination")
        except ValueError:
            need(False, f"OTLP {sig}: body is not JSON")

# syslog over UDP: RFC 5424, carrying the audit action
udp = [r["line"] for r in rs if r["kind"] == "syslog-udp"]
need(udp and all(re.match(r"^<\d+>1 \d{4}-\d\d-\d\dT", l) for l in udp), f"UDP syslog lines are not RFC 5424: {udp[:1]}")
need(any("ebpf.deny.add" in l for l in udp), "the audit event is missing from the UDP syslog stream")
need(len(udp) == len(set(udp)), "the same audit line was sent to syslog more than once")

# nothing secret in any request body
blob = "\n".join(r.get("body", "") + r.get("data", "") + r.get("line", "") for r in rs)
for name, s in (("webhook secret", hook_secret), ("bridge secret", bridge_secret), ("OTLP token", otlp_token)):
    need(s not in blob, f"the {name} appears in a delivered body")

print(json.dumps(problems))
PY
)"
python3 - "$RESULT_JSON" <<'PY' || exit 1
import json, sys
p = json.loads(sys.argv[1])
if p:
    print("FAIL: %d problem(s):" % len(p), file=sys.stderr)
    for x in p: print("  -", x, file=sys.stderr)
    sys.exit(1)
print("    every channel delivered in its own format, once; signatures, retry and severity filter verified; OTLP and syslog verified")
PY

echo "==> secrets appear nowhere the controller writes or serves"
for s in "$HOOK_SECRET" "$BRIDGE_SECRET" "$OTLP_TOKEN"; do
  if grep -q -- "$s" "$D/netrad.log"; then fail "a secret appears in the controller log"; fi
  for path in /api/v1/status /api/v1/features /api/v1/export/status /api/v1/audit /metrics; do
    if api "${BASE}${path}" 2>/dev/null | grep -q -- "$s"; then fail "a secret appears in GET ${path}"; fi
  done
done
echo "    log and API responses are clean"

echo "==> syslog over TCP"
kill "$NETRAD" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "$NETRAD" 2>/dev/null || break; sleep 0.25; done
start_netrad NETRA_SYSLOG_ADDR="127.0.0.1:${SYSLOG_PORT}" NETRA_SYSLOG_NETWORK=tcp NETRA_SYSLOG_INTERVAL=2s &
PIDS+=($!)
wait_ready
api -X POST -d '{"ip":"203.0.113.88","direction":"egress"}' "${BASE}/api/v1/ebpf/deny" >/dev/null
ok=0
for _ in $(seq 1 40); do
  if grep '"kind": "syslog-tcp"' "$D/received.jsonl" | grep -q '203.0.113.88'; then ok=1; break; fi
  sleep 0.5
done
[[ "$ok" == 1 ]] || { cut -c1-200 "$D/received.jsonl" | tail -5 >&2; fail "the TCP syslog stream never carried the new audit event"; }
grep '"kind": "syslog-tcp"' "$D/received.jsonl" | python3 -c '
import json, re, sys
lines = [json.loads(l)["line"] for l in sys.stdin]
bad = [l for l in lines if not re.match(r"^<\d+>1 \d{4}-\d\d-\d\dT", l)]
assert not bad, ("TCP syslog lines are not RFC 5424", bad[:1])
print("    %d RFC 5424 lines over TCP, one per line" % len(lines))'

echo "==> PASS sinks live"
