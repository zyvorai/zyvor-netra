#!/usr/bin/env bash
# Netra — TLS plaintext sampling, end to end (Linux, root)
#
# Real netrad + real netra-agent (NETRA_TLS_UPROBES=required, allowlist python3) on
# this host; a real HTTPS server and client (Python's ssl module, which calls
# OpenSSL's SSL_read_ex/SSL_write_ex) on loopback; real TLS between them.
# Asserts, through the controller's API and /metrics:
#
#   * per-role method and status counts arrive, exactly (the rate limit is off);
#   * the kernel counters show only allowlisted-process calls were sampled;
#   * PRIVACY: secrets planted in the URL path, query string, a cookie and a bearer
#     token appear nowhere the agent or controller exposes: not in
#     /api/v1/l7/tls, not in the agent's own report (/api/v1/agents), not in
#     /metrics, not in either process's log.
#
# Usage:
#   sudo ./scripts/ci-tlssample-smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTROLLER_PORT="${CONTROLLER_PORT:-30874}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${NETRA_API_KEY:-ci-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-agent-key}"
BIN_DIR="${BIN_DIR:-$(mktemp -d /tmp/netra-tls-bin.XXXXXX)}"
BPF_DIR="${BPF_DIR:-$(mktemp -d /tmp/netra-tls-bpf.XXXXXX)}"
PIN_PATH="${PIN_PATH:-/sys/fs/bpf/netra-ci-tls}"
HTTPS_PORT="${HTTPS_PORT:-48443}"
SECRET_PATH="TOPSECRETPATH-1a2b3c"
SECRET_QUERY="TOPSECRETQUERY-4d5e6f"
SECRET_COOKIE="TOPSECRETCOOKIE-7a8b9c"
SECRET_BEARER="TOPSECRETBEARER-0d1e2f"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
for c in go clang curl python3 openssl; do need_cmd "$c"; done
[[ "$(uname -s)" == "Linux" ]] || { echo "requires Linux (eBPF + uprobes)" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || { echo "run as root (BPF load + uprobe attach)" >&2; exit 1; }

PIDS=()
cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  # Bounded: a process that ignores SIGTERM must not hang the job in `wait`.
  for p in "${PIDS[@]}"; do
    for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$p" 2>/dev/null
    wait "$p" 2>/dev/null
  done
  rm -rf "$PIN_PATH" 2>/dev/null
}
trap cleanup EXIT

ARCH="$(uname -m)"
INC="/usr/include/${ARCH}-linux-gnu"
echo "==> compile BPF objects into ${BPF_DIR}"
for src in bpf/netra_*.c; do
  name="$(basename "$src" .c)"
  extra=()
  [[ "$name" == "netra_tc" ]] && extra=(-mllvm -bpf-stack-size=1024)
  clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" ${extra[@]+"${extra[@]}"} -c "$src" -o "${BPF_DIR}/${name}.o"
done

echo "==> build netrad + netra-agent"
mkdir -p "$BIN_DIR"
go build -o "${BIN_DIR}/netrad" ./cmd/netrad
go build -o "${BIN_DIR}/netra-agent" ./cmd/netra-agent

echo "==> start netrad on :${CONTROLLER_PORT}"
export NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY="$API_KEY" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_LISTEN=":${CONTROLLER_PORT}"
unset NETRA_TLS_CERT NETRA_TLS_KEY || true
"${BIN_DIR}/netrad" >/tmp/netra-tls-netrad.log 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do
  curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null && break
  sleep 0.25
done
curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null || { echo "controller never ready" >&2; tail -n 50 /tmp/netra-tls-netrad.log >&2; exit 1; }

echo "==> start netra-agent (NETRA_TLS_UPROBES=required, only python3 observed)"
rm -rf "$PIN_PATH"; mkdir -p "$PIN_PATH"
export NODE_NAME="ci-tls" NETRA_SERVER="$CONTROLLER" NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_BPF_OBJECT="${BPF_DIR}/netra_tc.o" NETRA_BPF_EDGE_OBJECT="${BPF_DIR}/netra_edge_intel.o"
export NETRA_BPF_CAPTURE_OBJECT="${BPF_DIR}/netra_capture.o" NETRA_BPF_TLSFP_OBJECT="${BPF_DIR}/netra_tlsfp.o"
export NETRA_BPF_SSL_OBJECT="${BPF_DIR}/netra_ssl.o" NETRA_BPF_PIN="$PIN_PATH"
export NETRA_CGROUP_PATH=/sys/fs/cgroup NETRA_CGROUP_ENABLED=true
export NETRA_TLSFP=off NETRA_L7=off NETRA_EDGE_INTEL=off NETRA_CAPTURE=off NETRA_TCX=off NETRA_INTERFACES='' NETRA_XDP_INTERFACES=''
export NETRA_TLS_UPROBES=required NETRA_TLS_UPROBES_COMMS=python3 NETRA_TLS_UPROBES_GAP=0s NETRA_TLS_UPROBES_RESCAN=1s
"${BIN_DIR}/netra-agent" >/tmp/netra-tls-agent.log 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")
for _ in $(seq 1 60); do
  grep -q 'TLS plaintext sampling attached' /tmp/netra-tls-agent.log 2>/dev/null && break
  kill -0 "$AGENT_PID" 2>/dev/null || { echo "agent exited early:" >&2; tail -n 60 /tmp/netra-tls-agent.log >&2; exit 1; }
  sleep 0.5
done
grep -q 'TLS plaintext sampling attached' /tmp/netra-tls-agent.log || { echo "the sampler never attached:" >&2; tail -n 60 /tmp/netra-tls-agent.log >&2; exit 1; }
echo "    sampler attached"

echo "==> real HTTPS server and client"
D="$(mktemp -d /tmp/netra-tls-cert.XXXXXX)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$D/k.pem" -out "$D/c.pem" -subj /CN=localhost -days 1 >/dev/null 2>&1
cat >/tmp/netra-tls-server.py <<'PY'
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = 503 if self.path.startswith("/down") else 200
        self.send_response(code); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv = http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("ready", flush=True)
srv.serve_forever()
PY
cat >/tmp/netra-tls-client.py <<'PY'
import os, ssl, sys, urllib.error, urllib.request
port = sys.argv[1]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
hdr = {"Cookie": "session=" + os.environ["SECRET_COOKIE"], "Authorization": "Bearer " + os.environ["SECRET_BEARER"]}
def get(path):
    req = urllib.request.Request("https://localhost:%s%s" % (port, path), headers=hdr)
    try:
        urllib.request.urlopen(req, context=ctx).read()
    except urllib.error.HTTPError:
        pass
for _ in range(12):
    get("/orders/%s?token=%s" % (os.environ["SECRET_PATH"], os.environ["SECRET_QUERY"]))
for _ in range(3):
    get("/down/%s?token=%s" % (os.environ["SECRET_PATH"], os.environ["SECRET_QUERY"]))
PY
python3 /tmp/netra-tls-server.py "$HTTPS_PORT" "$D/c.pem" "$D/k.pem" >/tmp/netra-tls-server.log 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do grep -q ready /tmp/netra-tls-server.log 2>/dev/null && break; sleep 0.25; done
grep -q ready /tmp/netra-tls-server.log || { echo "the HTTPS server did not start" >&2; cat /tmp/netra-tls-server.log >&2; exit 1; }
# The agent rescans for libssl every second; give it a moment to see the server.
sleep 2.5
SECRET_PATH="$SECRET_PATH" SECRET_QUERY="$SECRET_QUERY" SECRET_COOKIE="$SECRET_COOKIE" SECRET_BEARER="$SECRET_BEARER" \
  python3 /tmp/netra-tls-client.py "$HTTPS_PORT"

echo "==> wait for the samples to reach the controller"
fetch() { curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}$1"; }
# Exact: the rate limit is off and each request is its own TLS connection. Each
# request is seen once in each role: written by the client (issued) and read by
# the server (served), and the reverse for its response.
CHECK='
import json,sys
d=json.load(sys.stdin)
p={x["role"]:x for x in d.get("protocols",[]) if x["protocol"]=="http1"}
ops=lambda r:{o["op"]:o["count"] for o in p.get(r,{}).get("ops",[])}
codes=lambda r:{c["code"]:c["count"] for c in p.get(r,{}).get("codes",[])}
done=all(ops(r).get("GET")==15 and sum(codes(r).values())==15 for r in ("served","issued"))
if sys.argv[1]=="wait": sys.exit(0 if done else 1)
assert d["nodesReporting"]==1, d
# Only allowlisted (python3) calls are candidates, and the rate limit is off, so every
# candidate was sampled: the scale factor is exactly 1.
assert d["emitted"]>0 and d["eligible"]==d["emitted"] and d.get("scaleFactor",0)==1, ("kernel counters", d["eligible"], d["emitted"], d.get("scaleFactor"))
for r in ("served","issued"):
    assert ops(r)=={"GET":15}, (r, ops(r))
    assert codes(r)=={"200":12,"503":3}, (r, codes(r))
    assert p[r]["requests"]==15 and p[r]["responses"]==15 and p[r]["errors"]==3, (r, p[r])
hosts={(h["role"],h["host"],h["op"]):h["count"] for h in d.get("hosts",[])}
assert hosts=={("served","localhost","GET"):15,("issued","localhost","GET"):15}, ("host counts must be 15 per role, not 30 in one", hosts)
assert d["nodes"][0].get("libraries"), ("no instrumented library reported", d["nodes"])
print("    served :", ops("served"), codes("served"))
print("    issued :", ops("issued"), codes("issued"))
print("    hosts  :", hosts)
print("    libs   :", d["nodes"][0]["libraries"])
print("    kernel : eligible", d["eligible"], "emitted", d["emitted"], "scale", d.get("scaleFactor"))
'
ok=0
for _ in $(seq 1 40); do
  if fetch /api/v1/l7/tls | python3 -c "$CHECK" wait 2>/dev/null; then ok=1; break; fi
  sleep 0.5
done
if [[ "$ok" -ne 1 ]]; then
  echo "the exact expected counts never arrived; agent log and API:" >&2
  tail -n 40 /tmp/netra-tls-agent.log >&2; fetch /api/v1/l7/tls >&2 || true
  exit 1
fi
fetch /api/v1/l7/tls | python3 -c "$CHECK" final

echo "==> metrics carry the counts with bounded labels"
metrics="$(fetch /metrics)"
grep -q '^netra_tls_sample_requests{protocol="http1",role="served",op="GET"} 15$' <<<"$metrics" || { echo "no served GET series" >&2; exit 1; }
grep -q '^netra_tls_sample_error_codes{protocol="http1",role="issued",code="503"} 3$' <<<"$metrics" || { echo "no 503 series" >&2; exit 1; }
grep -q '^netra_tls_sample_nodes_reporting 1$' <<<"$metrics" || { echo "node not reporting" >&2; exit 1; }

echo "==> PRIVACY: secrets planted in the path, query string, cookie and bearer token appear nowhere"
leaks=0
for what in /api/v1/l7/tls /api/v1/l7/sampled /api/v1/agents /metrics; do
  if fetch "$what" | grep -q -e "$SECRET_PATH" -e "$SECRET_QUERY" -e "$SECRET_COOKIE" -e "$SECRET_BEARER"; then
    echo "LEAK: a planted secret appears in ${what}" >&2
    leaks=1
  fi
done
if grep -q -e "$SECRET_PATH" -e "$SECRET_QUERY" -e "$SECRET_COOKIE" -e "$SECRET_BEARER" /tmp/netra-tls-agent.log /tmp/netra-tls-netrad.log; then
  echo "LEAK: a planted secret appears in a log" >&2
  leaks=1
fi
(( leaks == 0 )) || exit 1
echo "    no secret in the API, the agent report, /metrics or the logs"

echo "==> PASS tls sample smoke"
