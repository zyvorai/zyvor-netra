#!/usr/bin/env bash
# Netra — sampled L7 protocol observation, end to end (Linux, root)
#
# Real netrad + real netra-agent (NETRA_L7_SAMPLE=required) on this host; small
# fake Redis and PostgreSQL servers on loopback; real TCP traffic between them.
# Asserts, through the controller's API and /metrics:
#
#   * Redis GET/SET counts and the error replies arrive as per-operation counts;
#   * PostgreSQL SELECT/INSERT and the SQLSTATE error class arrive;
#   * the kernel counters and scale factor are reported;
#   * PRIVACY: a secret planted in a Redis key and in a SQL literal appears
#     nowhere the agent or controller exposes: not in /api/v1/l7/sampled, not in
#     the agent's own report (/api/v1/agents), not in /metrics.
#
# Usage:
#   sudo ./scripts/ci-l7sample-smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTROLLER_PORT="${CONTROLLER_PORT:-30873}"
CONTROLLER="http://127.0.0.1:${CONTROLLER_PORT}"
API_KEY="${NETRA_API_KEY:-ci-api-key}"
AGENT_KEY="${NETRA_AGENT_KEY:-ci-agent-key}"
BIN_DIR="${BIN_DIR:-$(mktemp -d /tmp/netra-l7s-bin.XXXXXX)}"
BPF_DIR="${BPF_DIR:-$(mktemp -d /tmp/netra-l7s-bpf.XXXXXX)}"
PIN_PATH="${PIN_PATH:-/sys/fs/bpf/netra-ci-l7s}"
REDIS_PORT="${REDIS_PORT:-46379}"
PG_PORT="${PG_PORT:-45432}"
SECRET_KEY="TOPSECRETKEY-7c1f9a"
SECRET_SQL="TOPSECRETSQL-3d5e8b"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
for c in go clang curl python3; do need_cmd "$c"; done

[[ "$(uname -s)" == "Linux" ]] || { echo "requires Linux (eBPF + cgroup)" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || { echo "run as root (BPF load + cgroup attach)" >&2; exit 1; }

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
"${BIN_DIR}/netrad" >/tmp/netra-l7s-netrad.log 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do
  curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null && break
  sleep 0.25
done
curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}/api/v1/status" >/dev/null || { echo "controller never ready" >&2; tail -n 50 /tmp/netra-l7s-netrad.log >&2; exit 1; }

echo "==> start netra-agent (NETRA_L7_SAMPLE=required, redis:${REDIS_PORT} postgres:${PG_PORT})"
rm -rf "$PIN_PATH"; mkdir -p "$PIN_PATH"
export NODE_NAME="ci-l7s" NETRA_SERVER="$CONTROLLER" NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_BPF_OBJECT="${BPF_DIR}/netra_tc.o" NETRA_BPF_EDGE_OBJECT="${BPF_DIR}/netra_edge_intel.o"
export NETRA_BPF_CAPTURE_OBJECT="${BPF_DIR}/netra_capture.o" NETRA_BPF_TLSFP_OBJECT="${BPF_DIR}/netra_tlsfp.o"
export NETRA_BPF_L7SAMPLE_OBJECT="${BPF_DIR}/netra_l7sample.o" NETRA_BPF_PIN="$PIN_PATH"
export NETRA_CGROUP_PATH=/sys/fs/cgroup NETRA_CGROUP_ENABLED=true
export NETRA_TLSFP=off NETRA_L7=off NETRA_EDGE_INTEL=off NETRA_CAPTURE=off NETRA_TCX=off NETRA_INTERFACES='' NETRA_XDP_INTERFACES=''
export NETRA_L7_SAMPLE=required NETRA_L7_SAMPLE_PORTS="${REDIS_PORT}:redis,${PG_PORT}:postgres" NETRA_L7_SAMPLE_GAP=0s
"${BIN_DIR}/netra-agent" >/tmp/netra-l7s-agent.log 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")
for _ in $(seq 1 60); do
  grep -q 'L7 protocol sampling attached' /tmp/netra-l7s-agent.log 2>/dev/null && break
  kill -0 "$AGENT_PID" 2>/dev/null || { echo "agent exited early:" >&2; tail -n 60 /tmp/netra-l7s-agent.log >&2; exit 1; }
  sleep 0.5
done
grep -q 'L7 protocol sampling attached' /tmp/netra-l7s-agent.log || { echo "the sampler never attached:" >&2; tail -n 60 /tmp/netra-l7s-agent.log >&2; exit 1; }
echo "    sampler attached"

echo "==> fake Redis + PostgreSQL servers and real traffic"
cat >/tmp/netra-l7s-traffic.py <<'PY'
import os, socket, struct, threading, time
REDIS, PG = int(os.environ["REDIS_PORT"]), int(os.environ["PG_PORT"])
SECRET_KEY, SECRET_SQL = os.environ["SECRET_KEY"].encode(), os.environ["SECRET_SQL"]

def serve(port, handler):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(16)
    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

def redis(c):
    while True:
        d = c.recv(4096)
        if not d:
            return
        if d.startswith(b"*3"):                      # SET k v
            c.sendall(b"+OK\r\n")
        elif d.startswith(b"*2\r\n$3\r\nGET"):       # GET k
            c.sendall(b"$3\r\nval\r\n")
        else:
            c.sendall(b"-ERR unknown command\r\n")

def pgmsg(t, body):
    return t + struct.pack("!I", 4 + len(body)) + body

def pg(c):
    while True:
        d = c.recv(4096)
        if not d:
            return
        if d[:1] == b"Q":
            if b"missing" in d:
                c.sendall(pgmsg(b"E", b"SERROR\0C42P01\0Mrelation does not exist\0\0") + pgmsg(b"Z", b"I"))
            else:
                verb = d[5:].split(b" ")[0].upper()
                c.sendall(pgmsg(b"C", verb + b" 1\0") + pgmsg(b"Z", b"I"))

def resp(cmd, *args):
    out = b"*%d\r\n" % (1 + len(args)) + b"$%d\r\n%s\r\n" % (len(cmd), cmd)
    for a in args:
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out

def nodelay(port):
    s = socket.create_connection(("127.0.0.1", port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s

serve(REDIS, redis)
serve(PG, pg)

r = nodelay(REDIS)
for _ in range(30):
    r.sendall(resp(b"GET", SECRET_KEY)); r.recv(4096)
for _ in range(20):
    r.sendall(resp(b"SET", SECRET_KEY, b"v")); r.recv(4096)
for _ in range(5):
    r.sendall(resp(b"BADCMD", b"x")); r.recv(4096)

p = nodelay(PG)
def q(sql):
    b = sql.encode() + b"\0"
    p.sendall(b"Q" + struct.pack("!I", 4 + len(b)) + b)
    p.recv(4096)
for _ in range(10):
    q("SELECT '%s' FROM users" % SECRET_SQL)
for _ in range(5):
    q("INSERT INTO t VALUES ('%s')" % SECRET_SQL)
for _ in range(3):
    q("SELECT * FROM missing WHERE k = '%s'" % SECRET_SQL)
time.sleep(1)
PY
export REDIS_PORT PG_PORT SECRET_KEY SECRET_SQL
python3 /tmp/netra-l7s-traffic.py

echo "==> wait for the samples to reach the controller"
fetch() { curl -sf -H "Authorization: Bearer ${API_KEY}" "${CONTROLLER}$1"; }
# The counts are exact here: the rate limit is off (NETRA_L7_SAMPLE_GAP=0s) and
# every request is its own round trip, so each is one segment. Each request is seen
# once leaving the client (role "issued") and once arriving at the server (role
# "served"); the two roles are never added together.
CHECK='
import json,sys
d=json.load(sys.stdin)
p={(x["protocol"],x["role"]):x for x in d.get("protocols",[])}
ops=lambda n,r:{o["op"]:o["count"] for o in p.get((n,r),{}).get("ops",[])}
errs=lambda n,r:{c["code"]:c["count"] for c in p.get((n,r),{}).get("codes",[]) if c["status"]=="error"}
want_r={"GET":30,"SET":20,"OTHER":5}
want_p={"SELECT":13,"INSERT":5}
done=all(ops("redis",r)==want_r and ops("postgres",r)==want_p for r in ("served","issued"))
if sys.argv[1]=="wait": sys.exit(0 if done else 1)
assert d["nodesReporting"]==1, d
assert d["eligible"]>0 and d["emitted"]==d["eligible"] and d.get("scaleFactor",0)==1, ("kernel counters", d["eligible"], d["emitted"], d.get("scaleFactor"))
for r in ("served","issued"):
    assert ops("redis",r)==want_r, (r, "redis", ops("redis",r))
    assert ops("postgres",r)==want_p, (r, "postgres", ops("postgres",r))
# Errors are seen in the responses: 5 unknown Redis commands, 3 missing-table queries.
for r in ("served","issued"):
    assert errs("redis",r).get("ERR")==5, (r, errs("redis",r))
    assert errs("postgres",r).get("42")==3, (r, errs("postgres",r))
    assert p[("redis",r)]["errors"]==5 and p[("postgres",r)]["errors"]==3, (r,)
print("    redis   served :", ops("redis","served"), "errors", errs("redis","served"))
print("    redis   issued :", ops("redis","issued"))
print("    postgres served:", ops("postgres","served"), "errors", errs("postgres","served"))
print("    postgres issued:", ops("postgres","issued"))
print("    kernel  : eligible", d["eligible"], "emitted", d["emitted"], "scale", d["scaleFactor"])
'
ok=0
for _ in $(seq 1 40); do
  if fetch /api/v1/l7/sampled | python3 -c "$CHECK" wait 2>/dev/null; then ok=1; break; fi
  sleep 0.5
done
if [[ "$ok" -ne 1 ]]; then
  echo "the exact expected counts never arrived; agent log and API:" >&2
  tail -n 40 /tmp/netra-l7s-agent.log >&2; fetch /api/v1/l7/sampled >&2 || true
  exit 1
fi
fetch /api/v1/l7/sampled | python3 -c "$CHECK" final

echo "==> metrics carry the counts with bounded labels"
metrics="$(fetch /metrics)"
grep -q '^netra_l7_sample_requests{protocol="redis",role="served",op="GET"} 30$' <<<"$metrics" || { echo "no redis GET series" >&2; exit 1; }
grep -q '^netra_l7_sample_requests{protocol="postgres",role="issued",op="SELECT"} 13$' <<<"$metrics" || { echo "no postgres SELECT series" >&2; exit 1; }
grep -q '^netra_l7_sample_scale_factor ' <<<"$metrics" || { echo "no scale factor" >&2; exit 1; }

echo "==> PRIVACY: the planted secrets appear nowhere the agent or controller exposes"
leaks=0
for what in /api/v1/l7/sampled /api/v1/agents /metrics; do
  if fetch "$what" | grep -q -e "$SECRET_KEY" -e "$SECRET_SQL"; then
    echo "LEAK: a planted secret appears in ${what}" >&2
    leaks=1
  fi
done
if grep -q -e "$SECRET_KEY" -e "$SECRET_SQL" /tmp/netra-l7s-agent.log /tmp/netra-l7s-netrad.log; then
  echo "LEAK: a planted secret appears in a log" >&2
  leaks=1
fi
(( leaks == 0 )) || exit 1
echo "    no secret in the API, the agent report, /metrics or the logs"

echo "==> PASS l7 sample smoke"
