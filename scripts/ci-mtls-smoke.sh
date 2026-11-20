#!/usr/bin/env bash
# Netra — agent <-> controller mutual TLS, end to end.
#
# Real netrad and, on Linux as root, a real netra-agent, with real certificates
# made by openssl and real TLS between them. Asserts, from outside the process:
#
#   startup   netrad refuses NETRA_AGENT_MTLS without a CA, with an empty CA file,
#             over plain HTTP, and with a typo'd mode; it starts with none of them.
#   required  an agent-only request with the right agent key but no certificate is
#             refused (401); with a certificate from the agent CA it is accepted
#             (202); a certificate from another CA fails the handshake; a
#             certificate with the wrong key usage fails the handshake.
#   people    /healthz and an API-key request need no client certificate.
#   agent     (Linux, root) the real agent with NETRA_CLIENT_CERT/KEY reports and is
#             marked "mtls": true; the same agent without them is refused and never
#             appears; and with its certificate files replaced in place (and the
#             controller restarted trusting only the new CA) the same process
#             reports again, proving it re-reads them.
#
# Usage:
#   ./scripts/ci-mtls-smoke.sh              # controller half only (any OS)
#   sudo ./scripts/ci-mtls-smoke.sh         # plus the real agent (Linux)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${CONTROLLER_PORT:-30877}"
API_KEY="ci-api-key-mtls"
AGENT_KEY="ci-agent-key-mtls"
D="$(mktemp -d "${TMPDIR:-/tmp}/netra-mtls.XXXXXX")"
BIN="$D/bin"; mkdir -p "$BIN"
LOG="$D/netrad.log"
for c in go curl openssl; do command -v "$c" >/dev/null || { echo "missing required command: $c" >&2; exit 1; }; done

PIDS=()
cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  for p in "${PIDS[@]}"; do
    for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
  done
  [[ -n "${PIN_PATH:-}" ]] && rm -rf "$PIN_PATH"
  [[ "${KEEP:-}" == 1 ]] || rm -rf "$D"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; [[ -f "$LOG" ]] && tail -n 20 "$LOG" >&2; exit 1; }

echo "==> build netrad"
go build -o "$BIN/netrad" ./cmd/netrad

echo "==> PKI: agent CA, a client cert, a wrong-CA cert, a server-auth-only cert, a server cert"
cd "$D"
mkca() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$1.key" -out "$1.crt" -subj "/CN=$1" -days 2 >/dev/null 2>&1; }
# issue <ca> <name> <extendedKeyUsage> [days]
issue() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$2.key" -out "$2.csr" -subj "/CN=$2" >/dev/null 2>&1
  printf 'extendedKeyUsage=%s\nkeyUsage=digitalSignature\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' "$3" >"$2.ext"
  openssl x509 -req -in "$2.csr" -CA "$1.crt" -CAkey "$1.key" -CAcreateserial -out "$2.crt" -days "${4:-2}" -extfile "$2.ext" >/dev/null 2>&1
}
mkca agentca; mkca otherca
issue agentca agent1 clientAuth
issue otherca rogue clientAuth
issue agentca serveronly serverAuth
issue agentca netra-server serverAuth   # the controller's own certificate
cd "$ROOT"

netrad() { # netrad <log> <env...>: run in the background; exec so $! is netrad itself, not a subshell
  local out="$1"; shift
  exec env NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY="$API_KEY" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_LISTEN=":${PORT}" "$@" "$BIN/netrad" >"$out" 2>&1
}

echo "==> startup: netrad refuses every unsafe mTLS setting, before serving anything"
refuses() { # refuses <description> <env...>
  local what="$1"; shift
  local out="$D/refuse.log"
  if timeout 15 env NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY=k NETRA_AGENT_KEY=a NETRA_LISTEN=":$((PORT + 1))" "$@" "$BIN/netrad" >"$out" 2>&1; then
    fail "netrad started with $what"
  fi
  grep -q "secure startup refused" "$out" || { cat "$out" >&2; fail "netrad exited for $what, but not with a refusal"; }
  echo "    refused: $what"
}
: >"$D/empty.pem"
TLS=(NETRA_TLS_CERT="$D/netra-server.crt" NETRA_TLS_KEY="$D/netra-server.key")
refuses "mode=required and no CA"        "${TLS[@]}" NETRA_AGENT_MTLS=required
refuses "mode=required and an empty CA"  "${TLS[@]}" NETRA_AGENT_MTLS=required NETRA_AGENT_CLIENT_CA="$D/empty.pem"
refuses "mode=required and a missing CA" "${TLS[@]}" NETRA_AGENT_MTLS=required NETRA_AGENT_CLIENT_CA="$D/nope.pem"
refuses "mode=required over plain HTTP"  NETRA_AGENT_MTLS=required NETRA_AGENT_CLIENT_CA="$D/agentca.crt"
refuses "a typo'd mode"                  "${TLS[@]}" NETRA_AGENT_MTLS=requried NETRA_AGENT_CLIENT_CA="$D/agentca.crt"

echo "==> start netrad with NETRA_AGENT_MTLS=required"
netrad "$LOG" "${TLS[@]}" NETRA_AGENT_MTLS=required NETRA_AGENT_CLIENT_CA="$D/agentca.crt" &
NETRAD_PID=$!
PIDS+=("$NETRAD_PID")
CURL=(curl -s --max-time 10 --cacert "$D/agentca.crt" --resolve "localhost:${PORT}:127.0.0.1")
U="https://localhost:${PORT}"
for _ in $(seq 1 60); do "${CURL[@]}" -o /dev/null "$U/healthz" && break; sleep 0.25; done
"${CURL[@]}" -o /dev/null "$U/healthz" || fail "controller never became ready"
grep -q '"agentMTLS":"required"' "$LOG" || fail "netrad did not log agentMTLS=required"

code() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@"; }
REPORT='{"node":"smoke-curl","observedAt":"2026-01-01T00:00:00Z"}'
post() { code -X POST -H 'Content-Type: application/json' -H "X-Netra-Agent-Key: ${AGENT_KEY}" -d "$REPORT" "$@" "$U/api/v1/agents/report"; }

echo "==> required: certificate, key usage and issuer are all enforced"
c=$(post) || true;                                                              [[ "$c" == 401 ]] || fail "right key, no certificate: $c, want 401"
c=$(post --cert "$D/agent1.crt" --key "$D/agent1.key");                         [[ "$c" == 202 ]] || fail "right key + agent certificate: $c, want 202"
if post --cert "$D/rogue.crt" --key "$D/rogue.key" >/dev/null 2>&1; then fail "a certificate from another CA was accepted"; fi
if post --cert "$D/serveronly.crt" --key "$D/serveronly.key" >/dev/null 2>&1; then fail "a server-auth certificate was accepted as a client certificate"; fi
c=$(code -X POST -H 'Content-Type: application/json' -H "X-Netra-Agent-Key: wrong" --cert "$D/agent1.crt" --key "$D/agent1.key" -d "$REPORT" "$U/api/v1/agents/report") || true
[[ "$c" == 401 ]] || fail "certificate but wrong key: $c, want 401 (the certificate is a second factor)"
echo "    no cert 401 · agent cert 202 · other CA and wrong usage refused at the handshake · wrong key 401"

echo "==> required: people are not asked for a certificate"
c=$(code "$U/healthz");                                                         [[ "$c" == 200 ]] || fail "/healthz: $c"
c=$(code -H "Authorization: Bearer ${API_KEY}" "$U/api/v1/agents");             [[ "$c" == 200 ]] || fail "API key without a certificate: $c, want 200"
c=$(code -H "X-Netra-Agent-Key: ${AGENT_KEY}" "$U/api/v1/ebpf/config") || true; [[ "$c" == 401 ]] || fail "agent key alone on a shared route: $c, want 401"

echo "==> the controller records how each report arrived, and the agent cannot claim it"
J=$("${CURL[@]}" -H "Authorization: Bearer ${API_KEY}" "$U/api/v1/agents")
python3 - "$J" <<'PY' || fail "agents list"
import json, sys
d = json.loads(sys.argv[1]); a = d["items"]
n = {x["node"]: x for x in a}
assert n["smoke-curl"].get("mtls") is True, n["smoke-curl"]
PY
M=$("${CURL[@]}" -H "Authorization: Bearer ${API_KEY}" "$U/metrics")
grep -q '^netra_agent_mtls_rejected_total [1-9]' <<<"$M" || fail "no rejected counter"
grep -q '^netra_agent_mtls_reports_total [1-9]' <<<"$M" || fail "no verified-reports counter"
echo "    node marked mtls=true; counters present"

if [[ "$(uname -s)" != "Linux" || "${EUID}" -ne 0 || "${NO_AGENT:-}" == 1 ]]; then
  echo "==> (skipping the real-agent half: needs Linux and root)"
  echo "==> PASS mtls smoke (controller)"
  exit 0
fi

# ---- the real agent -------------------------------------------------------
BPF_DIR="$D/bpf"; mkdir -p "$BPF_DIR"
PIN_PATH="/sys/fs/bpf/netra-ci-mtls"
echo "==> compile the BPF objects and build netra-agent"
ARCH="$(uname -m)"; INC="/usr/include/${ARCH}-linux-gnu"
clang -target bpfel -O2 -g -Wall -Wextra -Werror -I"$INC" -mllvm -bpf-stack-size=1024 -c bpf/netra_tc.c -o "$BPF_DIR/netra_tc.o"
go build -o "$BIN/netra-agent" ./cmd/netra-agent

start_agent() { # start_agent <node> <log> <env...>
  local node="$1" out="$2"; shift 2
  rm -rf "$PIN_PATH"; mkdir -p "$PIN_PATH"
  env NODE_NAME="$node" NETRA_SERVER="$U" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_CA_FILE="$D/agentca.crt" \
    NETRA_BPF_OBJECT="$BPF_DIR/netra_tc.o" NETRA_BPF_PIN="$PIN_PATH" NETRA_CGROUP_PATH=/sys/fs/cgroup NETRA_CGROUP_ENABLED=true \
    NETRA_TLSFP=off NETRA_L7=off NETRA_EDGE_INTEL=off NETRA_CAPTURE=off NETRA_TCX=off NETRA_TCP_EVENTS=off NETRA_DROP_INFO=off \
    NETRA_INTERFACES='' NETRA_XDP_INTERFACES='' "$@" "$BIN/netra-agent" >"$out" 2>&1 &
  AGENT_PID=$!; PIDS+=("$AGENT_PID")
}
stop_agent() { kill "$AGENT_PID" 2>/dev/null || true; for _ in $(seq 1 40); do kill -0 "$AGENT_PID" 2>/dev/null || break; sleep 0.25; done; kill -9 "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; }
agents() { "${CURL[@]}" -H "Authorization: Bearer ${API_KEY}" "$U/api/v1/agents"; }
reported() { agents | python3 -c "import json,sys; d=json.load(sys.stdin); a=d['items']; n={x['node']:x for x in a}; x=n.get('$1'); sys.exit(0 if x and x.get('mtls') is $2 else 1)" 2>/dev/null; }
seen() { agents | python3 -c "import json,sys; d=json.load(sys.stdin); a=d['items']; sys.exit(0 if any(x['node']=='$1' for x in a) else 1)"; }

echo "==> the real agent WITHOUT a certificate is refused and never appears"
start_agent ci-nocert "$D/agent-nocert.log"
for _ in $(seq 1 24); do grep -q '401' "$D/agent-nocert.log" && break; kill -0 "$AGENT_PID" 2>/dev/null || { cat "$D/agent-nocert.log" >&2; fail "agent exited"; }; sleep 0.5; done
grep -q '401' "$D/agent-nocert.log" || { tail -n 30 "$D/agent-nocert.log" >&2; fail "the agent without a certificate was not refused (no 401 in its log)"; }
seen ci-nocert && fail "a report from an agent without a certificate was stored"
stop_agent
echo "    refused with 401; nothing stored"

echo "==> the real agent WITH a certificate reports and is marked mtls=true"
cp "$D/agent1.crt" "$D/live.crt"; cp "$D/agent1.key" "$D/live.key"
start_agent ci-cert "$D/agent-cert.log" NETRA_CLIENT_CERT="$D/live.crt" NETRA_CLIENT_KEY="$D/live.key"
ok=0; for _ in $(seq 1 60); do reported ci-cert True && { ok=1; break; }; kill -0 "$AGENT_PID" 2>/dev/null || { tail -n 30 "$D/agent-cert.log" >&2; fail "agent exited"; }; sleep 0.5; done
[[ "$ok" == 1 ]] || { tail -n 30 "$D/agent-cert.log" >&2; agents >&2; fail "the agent with a certificate never reported as mtls"; }
echo "    ci-cert reported, mtls=true"

echo "==> certificate replaced in place under a running agent, old certificate no longer trusted"
# Replacing the files is not enough to prove a reload: the agent's existing TLS
# connection would keep working with the old certificate. So also restart the
# controller trusting ONLY a new CA. The agent must reconnect, and it can only be
# verified if it presents the certificate it re-read from disk.
cd "$D"; mkca agentca2; issue agentca2 agent2 clientAuth; cd "$ROOT"
cp "$D/agent2.crt" "$D/live.crt"; cp "$D/agent2.key" "$D/live.key"
kill "$NETRAD_PID" 2>/dev/null || true
for _ in $(seq 1 40); do kill -0 "$NETRAD_PID" 2>/dev/null || break; sleep 0.25; done
kill -9 "$NETRAD_PID" 2>/dev/null || true
LOG="$D/netrad2.log"
netrad "$LOG" "${TLS[@]}" NETRA_AGENT_MTLS=required NETRA_AGENT_CLIENT_CA="$D/agentca2.crt" &
NETRAD_PID=$!
PIDS+=("$NETRAD_PID")
for _ in $(seq 1 60); do "${CURL[@]}" -o /dev/null "$U/healthz" && break; sleep 0.25; done
"${CURL[@]}" -o /dev/null "$U/healthz" || fail "the restarted controller never became ready"
# The old certificate is refused by the new controller (proves the trust really changed).
if post --cert "$D/agent1.crt" --key "$D/agent1.key" >/dev/null 2>&1; then fail "the old certificate is still trusted after the CA changed"; fi
ok=0; for _ in $(seq 1 60); do reported ci-cert True && { ok=1; break; }; kill -0 "$AGENT_PID" 2>/dev/null || { tail -n 30 "$D/agent-cert.log" >&2; fail "agent died after its certificate was replaced"; }; sleep 0.5; done
[[ "$ok" == 1 ]] || { tail -n 30 "$D/agent-cert.log" >&2; agents >&2; fail "the agent never reported to the controller that trusts only the new CA: it did not reload its certificate"; }
echo "    the same agent process reported with the certificate it re-read from disk"

echo "==> PASS mtls smoke"
