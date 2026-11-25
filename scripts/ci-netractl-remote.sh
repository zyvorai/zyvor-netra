#!/usr/bin/env bash
# Netra — full detailed remote netractl suite (not smoke)
#
# Runs every non-mutating catalog command against a live controller and
# prints a pass/fail board with response snippets. Mutating commands are
# skipped unless NETRA_CLI_ALLOW_MUTATE=1.
#
# Prerequisites: netractl on PATH (or bin/netractl / make build-cli), and
# NETRA_URL / NETRA_API_KEY / NETRA_TLS_INSECURE (or ~/.netra/env).
#
# Usage:
#   ./scripts/ci-netractl-remote.sh
#   NETRA_URL=https://host:30870 NETRA_TLS_INSECURE=true NETRA_API_KEY=... \
#     ./scripts/ci-netractl-remote.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Prefer explicit env (CI live gate). Skip ~/.netra when NETRA_SKIP_DOTENV=1
# so a developer lab config cannot hijack GitHub Actions / local CI.
if [[ "${NETRA_SKIP_DOTENV:-}" != "1" && -f "${HOME}/.netra/env" ]]; then
  # Only fill unset keys (do not clobber NETRA_URL already exported by caller).
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    k="${line%%=*}"
    v="${line#*=}"
    k="$(echo "$k" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    v="$(echo "$v" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^["'\'']//;s/["'\'']$//')"
    [[ -z "$k" ]] && continue
    if [[ -z "${!k:-}" ]]; then
      export "$k=$v"
    fi
  done < "${HOME}/.netra/env"
fi

: "${NETRA_URL:=https://127.0.0.1:30870}"
export NETRA_URL
# HTTP controllers (ci-netractl-live) need no TLS skip; HTTPS labs default true.
if [[ "$NETRA_URL" == https://* ]]; then
  export NETRA_TLS_INSECURE="${NETRA_TLS_INSECURE:-true}"
fi
if [[ -z "${NETRA_API_KEY:-}" && -f "${HOME}/.netra/api-key" ]]; then
  NETRA_API_KEY="$(cat "${HOME}/.netra/api-key")"
  export NETRA_API_KEY
fi

NETRACTL="${NETRACTL:-}"
if [[ -z "$NETRACTL" ]]; then
  if command -v netractl >/dev/null 2>&1; then
    NETRACTL="$(command -v netractl)"
  elif [[ -x "$ROOT/bin/netractl" ]]; then
    NETRACTL="$ROOT/bin/netractl"
  else
    echo "==> building netractl"
    make build-cli
    NETRACTL="$ROOT/bin/netractl"
  fi
fi

export NETRA_CLI_NO_BANNER=1
export NO_COLOR=1

ALLOW_MUTATE="${NETRA_CLI_ALLOW_MUTATE:-0}"
ACCEPT_API_ERRORS="${NETRA_CLI_ACCEPT_API_ERRORS:-0}"
SNIPPET_LINES="${SNIPPET_LINES:-12}"
CMD_TIMEOUT="${NETRA_CLI_CMD_TIMEOUT:-45}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
skip=0
FAILED=()

api_error_ok() {
  # Structured controller responses prove argv→HTTP wiring even when the
  # feature needs Cilium/Hubble/kube (live CI boots a bare netrad).
  grep -qE '^error: (Bad Request|Not Found|Conflict|Forbidden|Unauthorized|Method Not Allowed|Bad Gateway|Service Unavailable|Internal Server Error|Not Implemented)' "$1"
}

run_one() {
  local name="$1"
  local optional="$2"
  shift 2
  local out="$TMP/out-${name}.txt"
  local ec=0
  set +e
  if command -v timeout >/dev/null 2>&1; then
    timeout "$CMD_TIMEOUT" "$NETRACTL" "$@" >"$out" 2>&1
    ec=$?
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$CMD_TIMEOUT" "$NETRACTL" "$@" >"$out" 2>&1
    ec=$?
  else
    "$NETRACTL" "$@" >"$out" 2>&1
    ec=$?
  fi
  set -e
  if [[ $ec -eq 0 ]]; then
    echo "PASS  $name  →  $*"
    head -n "$SNIPPET_LINES" "$out" | sed 's/^/      | /'
    echo
    pass=$((pass + 1))
  elif { [[ "$optional" == "1" ]] || [[ "$ACCEPT_API_ERRORS" == "1" ]]; } && api_error_ok "$out"; then
    echo "PASS  $name  →  $*  (API answered)"
    head -n "$SNIPPET_LINES" "$out" | sed 's/^/      | /'
    echo
    pass=$((pass + 1))
  else
    echo "FAIL  $name  →  $*  (exit $ec)"
    head -n "$SNIPPET_LINES" "$out" | sed 's/^/      | /'
    echo
    fail=$((fail + 1))
    FAILED+=("$name")
  fi
}

echo "==> full detailed netractl remote suite"
echo "    NETRA_URL=$NETRA_URL"
echo "    netractl=$NETRACTL"
echo "    allow_mutate=$ALLOW_MUTATE"
echo

DUMP="$TMP/dump.txt"
go test ./cmd/netractl/ -count=1 -run TestDumpCLICommandsForRemote -v >"$DUMP" 2>&1

while IFS= read -r line; do
  case "$line" in
    *cli-command:*)
      payload="${line#*cli-command: }"
      ;;
    *)
      continue
      ;;
  esac
  IFS='|' read -r name mutating _is_local streaming optional filekind argstr <<<"$payload"
  if [[ "$mutating" == "1" && "$ALLOW_MUTATE" != "1" ]]; then
    echo "SKIP  $name  (mutating; set NETRA_CLI_ALLOW_MUTATE=1)"
    skip=$((skip + 1))
    continue
  fi
  if [[ "$streaming" == "1" ]]; then
    echo "SKIP  $name  (streaming; mock CI covers argv)"
    skip=$((skip + 1))
    continue
  fi

  args=()
  if [[ -n "$argstr" ]]; then
    # shellcheck disable=SC2206
    IFS=$'\t' read -r -a args <<<"$argstr"
  fi

  for i in "${!args[@]}"; do
    if [[ "${args[$i]}" == '$FILE' ]]; then
      case "$filekind" in
        policy)
          f="$TMP/policy.json"
          printf '%s\n' '{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"ci","namespace":"default"},"spec":{"endpointSelector":{"matchLabels":{"app":"web"}},"egress":[{"toCIDR":["10.0.0.0/8"]}]}}' >"$f"
          ;;
        intel)
          f="$TMP/intel.txt"
          printf '%s\n' '203.0.113.1' 'malicious.example.com' >"$f"
          ;;
        watchlist)
          f="$TMP/watch.txt"
          printf '%s\n' '10.0.0.1' 'app.internal' >"$f"
          ;;
        explain)
          f="$TMP/explain.json"
          printf '%s\n' '{"items":[{"node":"ci","containers":[]}]}' >"$f"
          ;;
        denyset)
          f="$TMP/ci.denyset"
          printf '%s\n' 'netra-denyset/1' 'name: ci' 'lease: 10m' 'deny cidr 203.0.113.0/24 egress' >"$f"
          ;;
        out)
          f="$TMP/archive-out.json"
          : >"$f"
          ;;
        bundle)
          # A real bundle from the live controller: verify and diff read it offline.
          f="$TMP/incident-bundle.json"
          "$NETRACTL" incident bundle --minutes 5 --out "$f" >/dev/null
          ;;
        *)
          f="$TMP/fixture.bin"
          : >"$f"
          ;;
      esac
      args[$i]="$f"
    fi
  done
  run_one "$name" "$optional" "${args[@]}"
done <"$DUMP"

# The same bundle through the API: verify and report are viewer-role POSTs that
# compute over the posted bytes, and the seal needs a controller-side key.
if command -v curl >/dev/null 2>&1; then
  live_bundle="$TMP/api-bundle.json"
  "$NETRACTL" incident bundle --minutes 5 --out "$live_bundle" >/dev/null
  curl_api() { curl -sS ${NETRA_TLS_INSECURE:+-k} -H "Authorization: Bearer ${NETRA_API_KEY:-}" "$@"; }
  if curl_api -X POST --data-binary "@$live_bundle" "$NETRA_URL/api/v1/incident/verify" | grep -q '"ok":true'; then
    pass=$((pass + 1)); echo "ok   api incident verify"
  else
    fail=$((fail + 1)); FAILED+=("api incident verify"); echo "FAIL api incident verify"
  fi
  if curl_api -X POST --data-binary "@$live_bundle" "$NETRA_URL/api/v1/incident/report" | grep -q 'netra-incident-report/1'; then
    pass=$((pass + 1)); echo "ok   api incident report"
  else
    fail=$((fail + 1)); FAILED+=("api incident report"); echo "FAIL api incident report"
  fi
  if curl_api "$NETRA_URL/api/v1/insights/dependency-drift" | grep -q 'netra-dependency-drift/1' &&
    curl_api "$NETRA_URL/api/v1/insights/volume-shift" | grep -q 'netra-volume-shift/1'; then
    pass=$((pass + 1)); echo "ok   api flow drift and volume shift"
  else
    fail=$((fail + 1)); FAILED+=("api flow drift"); echo "FAIL api flow drift"
  fi
  if curl_api "$NETRA_URL/api/v1/security/beacons" | grep -q 'netra-egress-beacons/1' &&
    curl_api "$NETRA_URL/api/v1/insights/volume-shift?baseline_mode=same-time" | grep -q '"baselineMode":"same-time"'; then
    pass=$((pass + 1)); echo "ok   api periodic egress and same-time baseline"
  else
    fail=$((fail + 1)); FAILED+=("api periodic egress"); echo "FAIL api periodic egress"
  fi
fi

echo
echo "==== summary ===="
echo "pass=$pass fail=$fail skip=$skip"
if [[ $fail -gt 0 ]]; then
  echo "failed:"
  printf '  - %s\n' "${FAILED[@]}"
  exit 1
fi
if [[ $pass -lt 1 ]]; then
  echo "no commands ran; dump may be empty:" >&2
  cat "$DUMP" >&2
  exit 1
fi
echo "ci-netractl-remote: ok"
