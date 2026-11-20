#!/usr/bin/env bash
# Netra — Loki push sink against a REAL Loki and a REAL netrad (GitHub CI)
#
# Boots a real Loki (multi-tenant: auth_enabled=true) and the real netrad with
# NETRA_LOKI_URL set, makes netrad produce audit events and block events, and
# reads them back through Loki's own query API. It checks what an operator
# would: events arrive once, under a small bounded label set, are queryable with
# `| json`, stay inside their tenant, and keep flowing after Loki goes away and
# comes back. No root or cluster.
#
# Needs a Loki binary: LOKI_BIN=/path/to/loki (CI installs a pinned release).
#
# Usage:
#   LOKI_BIN=$HOME/bin/loki ./scripts/ci-loki-live.sh
#   LOKI_PORT=13199 CONTROLLER_PORT=19094 LOKI_BIN=... ./scripts/ci-loki-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LOKI_BIN="${LOKI_BIN:-}"
if [[ -z "$LOKI_BIN" ]] || [[ ! -x "$LOKI_BIN" ]]; then
  echo "set LOKI_BIN to a Loki binary (>= 3.x)" >&2
  exit 2
fi
BIN_DIR="${BIN_DIR:-$ROOT/bin}"
LOKI_PORT="${LOKI_PORT:-3199}"
LOKI_GRPC_PORT="${LOKI_GRPC_PORT:-39199}"
CONTROLLER_PORT="${CONTROLLER_PORT:-18094}"
API_KEY="ci-loki-api-key"
AGENT_KEY="ci-loki-agent-key"
TENANT="ci-tenant"
API="http://127.0.0.1:${CONTROLLER_PORT}"
LOKI="http://127.0.0.1:${LOKI_PORT}"
WORK="$(mktemp -d)"
NETRAD_LOG="${WORK}/netrad.log"
LOKI_LOG="${WORK}/loki.log"

mkdir -p "$BIN_DIR"
echo "==> build netrad"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/netrad" ./cmd/netrad

LOKI_PID=""
NETRAD_PID=""
cleanup() {
  [[ -n "$NETRAD_PID" ]] && kill "$NETRAD_PID" 2>/dev/null || true
  [[ -n "$LOKI_PID" ]] && kill "$LOKI_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

cat >"${WORK}/loki.yaml" <<YAML
auth_enabled: true
server:
  http_listen_address: 127.0.0.1
  http_listen_port: ${LOKI_PORT}
  grpc_listen_address: 127.0.0.1
  grpc_listen_port: ${LOKI_GRPC_PORT}
common:
  instance_addr: 127.0.0.1
  path_prefix: ${WORK}/data
  storage:
    filesystem:
      chunks_directory: ${WORK}/data/chunks
      rules_directory: ${WORK}/data/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h
analytics:
  reporting_enabled: false
YAML

start_loki() {
  "$LOKI_BIN" -config.file="${WORK}/loki.yaml" >>"$LOKI_LOG" 2>&1 &
  LOKI_PID=$!
  for _ in $(seq 1 120); do
    curl -sf "${LOKI}/ready" >/dev/null 2>&1 && return 0
    kill -0 "$LOKI_PID" 2>/dev/null || { echo "loki exited early:" >&2; tail -n 30 "$LOKI_LOG" >&2; return 1; }
    sleep 1
  done
  echo "loki never became ready" >&2
  tail -n 30 "$LOKI_LOG" >&2
  return 1
}

echo "==> start loki (multi-tenant) on :${LOKI_PORT}"
start_loki

echo "==> start netrad on :${CONTROLLER_PORT} pushing to loki as tenant ${TENANT}"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
export NETRA_LOKI_URL="$LOKI"
export NETRA_LOKI_TENANT="$TENANT"
export NETRA_LOKI_INTERVAL=2s
export NETRA_LOKI_LABELS="cluster=ci"
unset NETRA_TLS_CERT NETRA_TLS_KEY NETRA_STATE_FILE || true
"${BIN_DIR}/netrad" >"$NETRAD_LOG" 2>&1 &
NETRAD_PID=$!
for _ in $(seq 1 80); do
  curl -sf "${API}/healthz" >/dev/null 2>&1 && break
  kill -0 "$NETRAD_PID" 2>/dev/null || { echo "netrad exited early:" >&2; tail -n 40 "$NETRAD_LOG" >&2; exit 1; }
  sleep 0.25
done
curl -sf "${API}/healthz" >/dev/null

FAIL=0
PASS=0
check() { # check <name> <want> <got>
  if [[ "$2" == "$3" ]]; then PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"
  else FAIL=$((FAIL + 1)); printf '  FAIL %s: want %s, got %s\n' "$1" "$2" "$3" >&2; fi
}

deny() { # deny <ip>: an operator changes enforcement -> an audit event
  curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' \
    --data "{\"ip\":\"$1\"}" "${API}/api/v1/ebpf/deny"
}

block_report() { # block_report <dst-ip>...: an agent reports blocked events
  python3 - "$API" "$AGENT_KEY" "$@" <<'PY'
import datetime, json, sys, urllib.request
api, key, *ips = sys.argv[1:]
now = datetime.datetime.now(datetime.timezone.utc)
events = [{"observedAt": (now + datetime.timedelta(milliseconds=i)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "action": "blocked",
           "sourceIp": "10.9.0.1", "destinationIp": ip, "destinationPort": 443, "protocol": "tcp", "reason": "denylist",
           "direction": "egress", "hook": "cgroup"} for i, ip in enumerate(ips)]
body = json.dumps({"observedAt": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "node": "ci-node-1", "mode": "observe",
                   "interfaces": [], "standalone": True, "stats": [], "events": events}).encode()
req = urllib.request.Request(api + "/api/v1/agents/report", data=body, method="POST",
                             headers={"Content-Type": "application/json", "X-Netra-Agent-Key": key})
with urllib.request.urlopen(req) as r:
    assert r.status == 202, r.status
PY
}

# lq <tenant> <logql>: lines from a Loki range query over the last hour.
lq() {
  local tenant=$1 query=$2 now
  now="$(python3 -c 'import time; print(time.time_ns())')"
  curl -s -G -H "X-Scope-OrgID: ${tenant}" "${LOKI}/loki/api/v1/query_range" \
    --data-urlencode "query=${query}" --data-urlencode "start=$((now - 3600000000000))" \
    --data-urlencode "end=$((now + 60000000000))" --data-urlencode "limit=1000" --data-urlencode "direction=forward" |
    python3 -c '
import sys, json
d = json.load(sys.stdin)
for s in d.get("data", {}).get("result", []):
    for v in s["values"]:
        print(v[1])'
}
count() { grep -c . || true; }
wait_for_lines() { # wait_for_lines <want> <tenant> <query>
  local want=$1 tenant=$2 query=$3 n=0
  for _ in $(seq 1 40); do
    n="$(lq "$tenant" "$query" | count)"
    [[ "$n" -ge "$want" ]] && { echo "$n"; return 0; }
    sleep 1
  done
  echo "$n"
}

# ---- 1. audit events ---------------------------------------------------------
echo "==> audit events reach Loki"
check "deny 198.51.100.1" 200 "$(deny 198.51.100.1)"
check "deny 198.51.100.2" 200 "$(deny 198.51.100.2)"
check "deny 198.51.100.3" 200 "$(deny 198.51.100.3)"
got="$(wait_for_lines 3 "$TENANT" '{job="netra",class="audit"} |~ "198.51.100.[123]"')"
check "three audit lines arrive" 3 "$got"
sleep 5 # several more cycles pass
# (Loki discards an identical entry it already holds, so this cannot catch a
# resend by itself; internal/lokipush's tests count requests at the receiver.)
check "still exactly three audit lines after further cycles" 3 "$(lq "$TENANT" '{job="netra",class="audit"} |~ "198.51.100.[123]"' | count)"
check "the line is JSON: | json filters on a field" 1 "$(lq "$TENANT" '{job="netra",class="audit"} | json | target="198.51.100.2"' | count)"
check "the static label from NETRA_LOKI_LABELS is applied" 3 "$(lq "$TENANT" '{job="netra",cluster="ci",class="audit"} |~ "198.51.100.[123]"' | count)"

# ---- 2. block events ---------------------------------------------------------
echo "==> block events reach Loki"
block_report 203.0.113.10 203.0.113.11
got="$(wait_for_lines 2 "$TENANT" '{job="netra",class="block",node="ci-node-1"}')"
check "two block lines under the node label" 2 "$got"
check "block events are queryable by field" 1 "$(lq "$TENANT" '{job="netra",class="block"} | json | target="203.0.113.11"' | count)"

# ---- 3. bounded labels -------------------------------------------------------
echo "==> label cardinality"
labels="$(curl -s -H "X-Scope-OrgID: ${TENANT}" "${LOKI}/loki/api/v1/labels" | python3 -c '
import sys, json
print(" ".join(sorted(json.load(sys.stdin)["data"])))')"
# service_name is added by Loki itself.
check "only bounded labels exist (no ip/target/actor label)" "class cluster job node service_name severity" "$labels"

# ---- 4. tenancy --------------------------------------------------------------
echo "==> tenancy"
check "another tenant sees nothing" 0 "$(lq other-tenant '{job="netra"}' | count)"
check "a request with no tenant is refused" 401 "$(curl -s -o /dev/null -w '%{http_code}' -X POST "${LOKI}/loki/api/v1/push" -H 'Content-Type: application/json' --data '{"streams":[]}')"

# ---- 5. Loki outage and recovery ---------------------------------------------
echo "==> Loki goes away and comes back"
kill "$LOKI_PID" 2>/dev/null || true
wait "$LOKI_PID" 2>/dev/null || true
LOKI_PID=""
check "netrad keeps serving while Loki is down" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${API_KEY}" "${API}/api/v1/status")"
check "operators can still act while Loki is down" 200 "$(deny 198.51.100.50)"
check "and again" 200 "$(deny 198.51.100.51)"
sleep 6 # several failed cycles: the events must be held, not skipped
start_loki
got="$(wait_for_lines 2 "$TENANT" '{job="netra",class="audit"} |~ "198.51.100.5[01]"')"
check "events made during the outage arrive once Loki is back" 2 "$got"

# ---- 6. secrets --------------------------------------------------------------
echo "==> secret hygiene"
if grep -qF -- "$API_KEY" "$NETRAD_LOG"; then check "netrad log free of the API key" clean leaked; else check "netrad log free of the API key" clean clean; fi

echo
echo "loki live: ${PASS} passed, ${FAIL} failed"
if [[ "$FAIL" -ne 0 ]]; then
  echo "--- netrad log (tail) ---" >&2
  tail -n 40 "$NETRAD_LOG" >&2 || true
  exit 1
fi
