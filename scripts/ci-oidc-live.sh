#!/usr/bin/env bash
# Netra — OIDC login + RBAC + metrics token against a REAL netrad (GitHub CI)
#
# Boots the real netrad binary next to cmd/netra-ci-idp (a throwaway OIDC
# provider), then drives the API over HTTP: the role ladder, every way a token
# can be wrong, IdP outage and recovery, audit attribution that a header cannot
# spoof, and the /metrics token gate. No cluster, root, or real IdP needed.
#
# Usage:
#   ./scripts/ci-oidc-live.sh
#   IDP_PORT=19091 CONTROLLER_PORT=19092 ./scripts/ci-oidc-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN_DIR="${BIN_DIR:-$ROOT/bin}"
IDP_PORT="${IDP_PORT:-18091}"
CONTROLLER_PORT="${CONTROLLER_PORT:-18092}"
API_KEY="ci-oidc-static-admin-key"
AGENT_KEY="ci-oidc-agent-key"
METRICS_TOKEN="ci-oidc-metrics-token"
IDP="http://127.0.0.1:${IDP_PORT}"
API="http://127.0.0.1:${CONTROLLER_PORT}"
TMP="${TMPDIR:-/tmp}"
IDP_LOG="${TMP}/netra-ci-oidc-idp.log"
LOG="${TMP}/netra-ci-oidc-netrad.log"

mkdir -p "$BIN_DIR"
echo "==> build netrad + netra-ci-idp"
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/netrad" ./cmd/netrad
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "${BIN_DIR}/netra-ci-idp" ./cmd/netra-ci-idp

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for() { # wait_for <what> <url> [curl args...]
  local what=$1 url=$2; shift 2
  for _ in $(seq 1 80); do
    if curl -sf "$@" "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  echo "timed out waiting for $what ($url)" >&2
  return 1
}

echo "==> start netra-ci-idp on :${IDP_PORT}"
"${BIN_DIR}/netra-ci-idp" -addr "127.0.0.1:${IDP_PORT}" >"$IDP_LOG" 2>&1 &
PIDS+=($!)
wait_for "idp" "${IDP}/healthz"

echo "==> start netrad on :${CONTROLLER_PORT} with OIDC"
export NETRA_ALLOW_UNAUTHENTICATED=false
export NETRA_API_KEY="$API_KEY"
export NETRA_AGENT_KEY="$AGENT_KEY"
export NETRA_METRICS_TOKEN="$METRICS_TOKEN"
export NETRA_LISTEN=":${CONTROLLER_PORT}"
export NETRA_OIDC_ISSUER="$IDP"
export NETRA_OIDC_AUDIENCE="netra"
export NETRA_OIDC_ALLOW_INSECURE_HTTP=true
unset NETRA_TLS_CERT NETRA_TLS_KEY NETRA_STATE_FILE || true
"${BIN_DIR}/netrad" >"$LOG" 2>&1 &
NETRAD_PID=$!
PIDS+=("$NETRAD_PID")
wait_for "netrad" "${API}/healthz"

FAIL=0
PASS=0
check() { # check <name> <want> <got>
  if [[ "$2" == "$3" ]]; then
    PASS=$((PASS + 1))
    printf '  ok   %s\n' "$1"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL %s: want %s, got %s\n' "$1" "$2" "$3" >&2
  fi
}
not_denied() { # not_denied <name> <got>: request cleared authn+authz (handler may answer anything else)
  case "$2" in
    401 | 403 | 503) FAIL=$((FAIL + 1)); printf '  FAIL %s: got %s (was denied)\n' "$1" "$2" >&2 ;;
    *) PASS=$((PASS + 1)); printf '  ok   %s (%s)\n' "$1" "$2" ;;
  esac
}

code() { # code <METHOD> <path> <bearer> [body] [extra header]
  local method=$1 path=$2 bearer=$3 body=${4:-} extra=${5:-}
  local args=(-s -o /dev/null -w '%{http_code}' -X "$method")
  [[ -n "$bearer" ]] && args+=(-H "Authorization: Bearer ${bearer}")
  [[ -n "$extra" ]] && args+=(-H "$extra")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data "$body")
  curl "${args[@]}" "${API}${path}"
}
mint() { curl -sf "${IDP}/token?$1"; } # mint 'roles=admin&email=a@b'

# ---- 1. Cold-start IdP outage: 503 (not 401), static key still works --------
echo "==> IdP outage at first use"
TOK_ADMIN="$(mint 'roles=admin&email=root@example.com&sub=u-admin')" # /token stays up
curl -sf "${IDP}/down?on=1" >/dev/null
check "JWT while IdP is down -> 503 (transient, not a logout)" 503 "$(code GET /api/v1/whoami "$TOK_ADMIN")"
check "static admin key while IdP is down (break-glass)" 200 "$(code GET /api/v1/whoami "$API_KEY")"
curl -sf "${IDP}/down?on=0" >/dev/null
echo "    waiting for the verifier's refresh back-off to elapse..."
recovered=0
for _ in $(seq 1 60); do
  if [[ "$(code GET /api/v1/whoami "$TOK_ADMIN")" == 200 ]]; then recovered=1; break; fi
  sleep 1
done
check "recovers on its own once the IdP is back" 1 "$recovered"

# ---- 2. Identity and role resolution ---------------------------------------
echo "==> whoami"
TOK_VIEWER="$(mint 'roles=viewer&email=vi@example.com&sub=u-viewer')"
TOK_OPERATOR="$(mint 'roles=operator&email=op@example.com&sub=u-op')"
who() { curl -sf -H "Authorization: Bearer $1" "${API}/api/v1/whoami" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('kind'),d.get('role'),d.get('identity',''))"; }
check "viewer whoami" "oidc viewer oidc:vi@example.com" "$(who "$TOK_VIEWER")"
check "operator whoami" "oidc operator oidc:op@example.com" "$(who "$TOK_OPERATOR")"
check "admin whoami" "oidc admin oidc:root@example.com" "$(who "$TOK_ADMIN")"
check "static key whoami" "apikey admin " "$(who "$API_KEY")"

# ---- 3. Role ladder ---------------------------------------------------------
echo "==> role ladder"
DENY='{"ip":"198.51.100.7"}'
check "viewer reads" 200 "$(code GET /api/v1/agents "$TOK_VIEWER")"
not_denied "viewer may run a preview (POST, read-only)" "$(code POST /api/v1/ebpf/deny/preview "$TOK_VIEWER" '{"ip":"198.51.100.7"}')"
check "viewer cannot change enforcement" 403 "$(code POST /api/v1/ebpf/deny "$TOK_VIEWER" "$DENY")"
check "viewer cannot delete a rule" 403 "$(code DELETE /api/v1/ebpf/deny/198.51.100.7 "$TOK_VIEWER")"
check "viewer cannot download packet captures" 403 "$(code GET /api/v1/capture/artifacts/abc "$TOK_VIEWER")"
check "operator cannot change fleet posture" 403 "$(code PUT /api/v1/ebpf/mode "$TOK_OPERATOR" '{"mode":"observe"}')"
check "operator cannot apply cluster policy" 403 "$(code POST /api/v1/policies/lockdown "$TOK_OPERATOR" '{}')"
not_denied "operator changes enforcement" "$(code POST /api/v1/ebpf/deny "$TOK_OPERATOR" "$DENY")"
not_denied "admin changes fleet posture" "$(code PUT /api/v1/ebpf/mode "$TOK_ADMIN" '{"mode":"observe"}')"
not_denied "static key is admin" "$(code PUT /api/v1/ebpf/mode "$API_KEY" '{"mode":"observe"}')"

# ---- 4. Every way a token can be wrong --------------------------------------
echo "==> bad tokens"
check "no credential" 401 "$(code GET /api/v1/agents '')"
check "wrong static key" 401 "$(code GET /api/v1/agents 'not-the-key')"
check "garbage" 401 "$(code GET /api/v1/agents 'not.a.jwt')"
check "expired" 401 "$(code GET /api/v1/agents "$(mint 'roles=admin&ttl=-3600')")"
check "wrong audience (minted for another app)" 401 "$(code GET /api/v1/agents "$(mint 'roles=admin&aud=some-other-app')")"
check "wrong issuer" 401 "$(code GET /api/v1/agents "$(mint 'roles=admin&iss=https://evil.example')")"
check "valid token, no netra role" 403 "$(code GET /api/v1/agents "$(mint 'roles=random-group')")"
# Tamper: keep the viewer token's signature, swap in an admin payload.
FORGED="$(python3 - "$TOK_VIEWER" "$TOK_ADMIN" <<'PY'
import sys
v, a = sys.argv[1].split('.'), sys.argv[2].split('.')
print('.'.join([v[0], a[1], v[2]]))
PY
)"
check "tampered payload (viewer signature, admin claims)" 401 "$(code GET /api/v1/agents "$FORGED")"
# alg=none, hand-built.
NONE_TOKEN="$(python3 - <<'PY'
import base64, json
b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b'=').decode()
print(b({"alg": "none", "typ": "JWT"}) + '.' + b({"iss": "x", "aud": "netra", "roles": ["admin"], "exp": 9999999999}) + '.')
PY
)"
check "alg=none" 401 "$(code GET /api/v1/agents "$NONE_TOKEN")"

# ---- 5. Audit attribution ---------------------------------------------------
echo "==> audit attribution (X-Netra-Actor is client-controlled)"
code POST /api/v1/ebpf/deny "$TOK_OPERATOR" "$DENY" 'X-Netra-Actor: root' >/dev/null
audit_actors="$(curl -sf -H "Authorization: Bearer ${TOK_VIEWER}" "${API}/api/v1/audit?limit=200" | python3 -c "
import sys, json
print(' '.join(sorted({i.get('actor','') for i in json.load(sys.stdin).get('items', [])})))")"
echo "    actors seen in audit: ${audit_actors:-<none>}"
case " $audit_actors " in *" oidc:op@example.com "*) check "audit names the verified identity" ok ok ;; *) check "audit names the verified identity" ok "missing" ;; esac
case " $audit_actors " in *" root "*) check "spoofed X-Netra-Actor is not recorded for an OIDC caller" absent present ;; *) check "spoofed X-Netra-Actor is not recorded for an OIDC caller" absent absent ;; esac

# ---- 6. /metrics token gate -------------------------------------------------
echo "==> /metrics"
check "no credential" 401 "$(code GET /metrics '')"
check "wrong token" 401 "$(code GET /metrics 'nope')"
check "metrics token" 200 "$(code GET /metrics "$METRICS_TOKEN")"
check "admin static key" 200 "$(code GET /metrics "$API_KEY")"
check "viewer JWT" 200 "$(code GET /metrics "$TOK_VIEWER")"
check "token in the query string is not accepted" 401 "$(code GET "/metrics?token=${METRICS_TOKEN}" '')"
check "health probe stays open" 200 "$(code GET /healthz '')"
denied="$(curl -sf -H "Authorization: Bearer ${METRICS_TOKEN}" "${API}/metrics" | awk '/^netra_rbac_denied_total /{print $2}')"
if [[ "${denied:-0}" -ge 1 ]]; then check "netra_rbac_denied_total counts refusals" ok ok; else check "netra_rbac_denied_total counts refusals" ">=1" "${denied:-0}"; fi

# ---- 7. Secrets do not leak into the log -----------------------------------
echo "==> secret hygiene"
for secret in "$API_KEY" "$METRICS_TOKEN" "$TOK_ADMIN" "$TOK_OPERATOR" "$TOK_VIEWER"; do
  if grep -qF -- "$secret" "$LOG"; then
    check "netrad log free of secret ${secret:0:12}..." clean leaked
  else
    check "netrad log free of secret ${secret:0:12}..." clean clean
  fi
done

echo
echo "oidc live: ${PASS} passed, ${FAIL} failed"
if [[ "$FAIL" -ne 0 ]]; then
  echo "--- netrad log (tail) ---" >&2
  tail -n 60 "$LOG" >&2 || true
  exit 1
fi
