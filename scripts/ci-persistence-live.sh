#!/usr/bin/env bash
# Netra — controller state survives restarts, and is never silently lost (any OS, no root)
#
# Real `netrad` with NETRA_STATE_FILE (docs/high-availability.md). Asserts:
#
#   durability     rules, allow lists, the audit trail and the behaviour baseline
#                  written through the API survive a kill -9 (no chance to flush)
#                  and a graceful restart; the revision counter never goes backwards
#   security       an enforcement lease is NEVER resurrected: the controller comes
#                  back in observe with no lease, whatever was on disk
#   safety         a second controller on the same state file is refused; a corrupt
#                  or unsupported-schema file stops startup and is left untouched
#                  (never overwritten with an empty state); a damaged flow-history
#                  sidecar is set aside and does not stop the controller
#   control        without NETRA_STATE_FILE the same rules are gone after a restart,
#                  so the assertions above prove the file, not luck
#
# Usage:
#   ./scripts/ci-persistence-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

D="$(mktemp -d "${TMPDIR:-/tmp}/netra-persist.XXXXXX")"
PORT="${CONTROLLER_PORT:-18091}"
PORT2=$((PORT + 1))
API_KEY="ci-persist-api-key"
AGENT_KEY="ci-persist-agent-key"
STATE="$D/state/netra.json"
BASE="http://127.0.0.1:${PORT}"
command -v python3 >/dev/null || { echo "missing required command: python3" >&2; exit 1; }

PID=""
reap() { # reap <pid>: TERM, bounded wait, KILL
  local p="$1"
  [[ -n "$p" ]] || return 0
  kill "$p" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
  kill -9 "$p" 2>/dev/null || true
  wait "$p" 2>/dev/null || true
}
cleanup() { set +e; reap "$PID"; [[ "${KEEP:-}" == 1 ]] || rm -rf "$D"; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; [[ -f "$D/netrad.log" ]] && tail -n 15 "$D/netrad.log" >&2; exit 1; }

echo "==> build netrad"
CGO_ENABLED=0 go build -trimpath -o "$D/netrad" ./cmd/netrad

# start <port> <extra env...>: run in the background; exec so $! is netrad itself.
start() {
  local port="$1"; shift
  exec env NETRA_ALLOW_UNAUTHENTICATED=false NETRA_API_KEY="$API_KEY" NETRA_AGENT_KEY="$AGENT_KEY" NETRA_LISTEN=":${port}" "$@" "$D/netrad" >>"$D/netrad.log" 2>&1
}
boot() { # boot <extra env...>: start on $PORT, wait until ready, set PID
  start "$PORT" "$@" &
  PID=$!
  for _ in $(seq 1 60); do
    curl -sf -H "Authorization: Bearer ${API_KEY}" "${BASE}/api/v1/status" >/dev/null 2>&1 && return 0
    kill -0 "$PID" 2>/dev/null || fail "netrad exited during startup"
    sleep 0.25
  done
  fail "netrad never became ready"
}
api() { # api <method> <path> [json body]
  local m="$1" p="$2"; shift 2
  if [[ $# -gt 0 ]]; then
    curl -sf -X "$m" -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' -d "$1" "${BASE}${p}"
  else
    curl -sf -X "$m" -H "Authorization: Bearer ${API_KEY}" "${BASE}${p}"
  fi
}
py() { python3 -c "$@"; }

echo "==> write state through the API, then kill -9 (no chance to flush)"
mkdir -p "$D/state"
boot NETRA_STATE_FILE="$STATE"
api PUT "/api/v1/ebpf/mode?lease=10m" '{"mode":"enforce"}' >/dev/null
api POST /api/v1/ebpf/deny '{"ip":"203.0.113.5","direction":"both"}' >/dev/null
api POST /api/v1/ebpf/deny '{"ip":"2001:db8::5","direction":"egress"}' >/dev/null
api POST /api/v1/ebpf/cidr '{"cidr":"198.51.100.0/24"}' >/dev/null
api POST /api/v1/ebpf/allow '{"ip":"192.0.2.44"}' >/dev/null
api POST /api/v1/insights/baseline >/dev/null
before="$(api GET /api/v1/ebpf/config)"
base_before="$(api GET /api/v1/insights/baseline)"
py 'import json,sys; c=json.loads(sys.argv[1]); assert c["mode"]=="enforce" and c["leaseSeconds"]>0, c' "$before"
kill -9 "$PID"; wait "$PID" 2>/dev/null || true; PID=""

echo "==> after kill -9: rules survive; the enforcement lease does not"
boot NETRA_STATE_FILE="$STATE"
after="$(api GET /api/v1/ebpf/config)"
python3 - "$before" "$after" <<'PY' || fail "state after kill -9"
import json, sys
b, a = json.loads(sys.argv[1]), json.loads(sys.argv[2])
for k in ("blockedIPv4", "blockedIngressIPv4", "blockedIPv6", "blockedCidrs", "allowedIPv4"):
    assert a.get(k) == b.get(k), (k, "before", b.get(k), "after", a.get(k))
assert a["blockedIPv4"] == ["203.0.113.5"] and a["blockedIPv6"] == ["2001:db8::5"], a
assert a["mode"] == "observe", ("an enforcement lease was resurrected from disk", a["mode"])
assert not a.get("enforceUntil") and not a.get("leaseSeconds"), ("a lease survived the restart", a)
assert a["revision"] >= b["revision"], ("the revision counter went backwards", b["revision"], a["revision"])
print("    rules intact; mode observe, no lease; revision %d -> %d" % (b["revision"], a["revision"]))
PY
base_after="$(api GET /api/v1/insights/baseline)"
py 'import json,sys; b,a=json.loads(sys.argv[1]),json.loads(sys.argv[2]); assert a["baseline"]["capturedAt"]==b["baseline"]["capturedAt"], (b,a)' "$base_before" "$base_after" || fail "the behaviour baseline did not survive"
audit="$(api GET "/api/v1/audit?limit=200")"
python3 - "$audit" <<'PY' || fail "audit trail after restart"
import json, sys
ev = json.loads(sys.argv[1])["items"]
acts = {e["action"] for e in ev}
assert "ebpf.mode" in acts, ("the mode change is missing from the audit trail", sorted(acts))
assert any("203.0.113.5" in json.dumps(e) for e in ev), "the deny event is missing from the audit trail"
assert all(e.get("actor") for e in ev), "an audit event lost its actor"
print("    audit trail intact: %d events, actions %s" % (len(ev), sorted(acts)))
PY

echo "==> a mutation after restart continues the revision, and survives a graceful restart"
rev_before="$(py 'import json,sys; print(json.loads(sys.argv[1])["revision"])' "$after")"
api POST /api/v1/ebpf/deny '{"ip":"203.0.113.6","direction":"egress"}' >/dev/null
reap "$PID"; PID=""
boot NETRA_STATE_FILE="$STATE"
final="$(api GET /api/v1/ebpf/config)"
py 'import json,sys; c=json.loads(sys.argv[1]); r=int(sys.argv[2]); assert "203.0.113.6" in c["blockedIPv4"] and "203.0.113.5" in c["blockedIPv4"], c; assert c["revision"]>r, (c["revision"], r)' "$final" "$rev_before" || fail "graceful restart lost a rule or reused a revision"
echo "    both deny rules present; revision advanced past ${rev_before}"

echo "==> a second controller on the same state file is refused"
rc=0; timeout 20 bash -c "$(declare -f start); D='$D'; API_KEY='$API_KEY'; AGENT_KEY='$AGENT_KEY'; start ${PORT2} NETRA_STATE_FILE='$STATE'" >/dev/null 2>&1 || rc=$?
[[ "$rc" != 0 && "$rc" != 124 ]] || fail "a second controller started on a locked state file (rc=$rc)"
grep -q "locked by another Netra controller" "$D/netrad.log" || fail "the refusal did not say the file is locked"
echo "    refused: state file is locked by another Netra controller"

echo "==> a corrupt or unsupported state file stops startup and is left untouched"
reap "$PID"; PID=""
cp "$STATE" "$D/state.good"
printf '{this is not json' >"$STATE"
rc=0; timeout 20 bash -c "$(declare -f start); D='$D'; API_KEY='$API_KEY'; AGENT_KEY='$AGENT_KEY'; start ${PORT2} NETRA_STATE_FILE='$STATE'" >/dev/null 2>&1 || rc=$?
[[ "$rc" != 0 && "$rc" != 124 ]] || fail "netrad started on a corrupt state file (rc=$rc)"
[[ "$(cat "$STATE")" == '{this is not json' ]] || fail "a corrupt state file was overwritten instead of preserved"
py 'import json; d=json.load(open("'"$D"'/state.good")); d["schemaVersion"]=99; json.dump(d, open("'"$STATE"'","w"))'
rc=0; timeout 20 bash -c "$(declare -f start); D='$D'; API_KEY='$API_KEY'; AGENT_KEY='$AGENT_KEY'; start ${PORT2} NETRA_STATE_FILE='$STATE'" >/dev/null 2>&1 || rc=$?
[[ "$rc" != 0 && "$rc" != 124 ]] || fail "netrad started on an unsupported schema version (rc=$rc)"
grep -q '"schemaVersion": *99\|"schemaVersion":99' "$STATE" || fail "an unsupported-schema state file was rewritten"
echo "    both refused; neither file was modified"

echo "==> a damaged flow-history sidecar is set aside and does not stop the controller"
cp "$D/state.good" "$STATE"
printf 'garbage, not a flow log\n' >"${STATE}.flows"
boot NETRA_STATE_FILE="$STATE"
[[ -f "${STATE}.flows.bad" ]] || fail "the damaged sidecar was not set aside as .flows.bad"
py 'import json,sys; c=json.loads(sys.argv[1]); assert "203.0.113.6" in c["blockedIPv4"], c' "$(api GET /api/v1/ebpf/config)" || fail "the rules were lost while recovering from a bad sidecar"
echo "    controller up with its rules; sidecar kept as .flows.bad"
reap "$PID"; PID=""

echo "==> control: without NETRA_STATE_FILE the same rule is gone after a restart"
boot
api POST /api/v1/ebpf/deny '{"ip":"203.0.113.77","direction":"egress"}' >/dev/null
reap "$PID"; PID=""
boot
py 'import json,sys; c=json.loads(sys.argv[1]); assert "203.0.113.77" not in (c.get("blockedIPv4") or []), c' "$(api GET /api/v1/ebpf/config)" || fail "state persisted without a state file: the assertions above would prove nothing"
echo "    ephemeral controller starts empty"

echo "==> PASS persistence live"
