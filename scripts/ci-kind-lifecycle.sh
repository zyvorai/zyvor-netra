#!/usr/bin/env bash
# Netra — install, upgrade, rollback and restart on a real cluster (kind)
#
# Needs a running kind cluster (CI creates one with helm/kind-action), docker, helm,
# kubectl. Everything is built locally and loaded into kind; nothing is pulled from a
# registry. The whole life of a release, on the chart and images of this checkout:
#
#   install     the PREVIOUS release (the newest tag before HEAD, built from source) installs
#               with its own chart and a persistent volume, and takes state through its API
#   upgrade     `helm upgrade --reset-then-reuse-values` to HEAD, as operators do: the
#               controller rolls, the state (rules, baseline) survives on the volume, the
#               same API key still works, the version changes, and the node agent
#               DaemonSet, new in this step, starts, reports, and gets its config
#   restart     deleting the controller pod brings it back with its state
#   rollback    `helm rollback` returns to the previous release with the state still readable
#
# Usage:
#   ./scripts/ci-kind-lifecycle.sh                       # cluster name netra-ci
#   CLUSTER=mine PREVIOUS_TAG=v0.27.97 ./scripts/ci-kind-lifecycle.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLUSTER="${CLUSTER:-netra-ci}"
NS=netra-system
API_KEY="ci-kind-api-key"
AGENT_KEY="ci-kind-agent-key"
HEAD_VERSION="$(sed -n 's/^const version = "\(.*\)"$/\1/p' cmd/netrad/main.go)"
# The newest release tag with a DIFFERENT version than this checkout: commits on top of a fresh tag
# still carry that tag's version, and upgrading a release to itself proves nothing (and trips the
# "nothing is being upgraded" assertion below).
PREVIOUS_TAG="${PREVIOUS_TAG:-$(git tag --list 'v[0-9]*' --sort=-v:refname | while read -r t; do [[ "${t#v}" != "$HEAD_VERSION" ]] && { echo "$t"; break; }; done)}"
if [[ -z "$PREVIOUS_TAG" ]]; then
  # No release tag means no upgrade to test. CI opts in to a loud skip (a warning annotation on the run);
  # a local run stays strict so the gap is not hidden from whoever is checking an upgrade.
  if [[ "${ALLOW_NO_PREVIOUS_TAG:-}" == 1 ]]; then
    echo "::warning title=kind-lifecycle skipped::no release tag exists to upgrade from, so the install, upgrade and rollback test did not run"
    echo "SKIPPED kind lifecycle: no previous release tag (push a vX.Y.Z tag to enable it)"
    exit 0
  fi
  echo "no previous release tag to upgrade from (fetch tags: git fetch --tags)" >&2; exit 1
fi
for c in docker helm kubectl kind curl python3 git; do command -v "$c" >/dev/null || { echo "missing required command: $c" >&2; exit 1; }; done
W="$(mktemp -d "${TMPDIR:-/tmp}/netra-kind.XXXXXX")"
PF=""
cleanup() { set +e; [[ -n "$PF" ]] && kill "$PF" 2>/dev/null; [[ "${KEEP:-}" == 1 ]] || rm -rf "$W"; }
trap cleanup EXIT

dump() {
  kubectl -n "$NS" get all,pvc,events -o wide 2>&1 | tail -40 >&2 || true
  kubectl -n "$NS" logs deploy/netra --tail=30 >&2 2>&1 || true
  kubectl -n "$NS" logs ds/netra-agent --tail=30 >&2 2>&1 || true
}
fail() { echo "FAIL: $*" >&2; dump; exit 1; }

echo "==> previous release ${PREVIOUS_TAG} -> HEAD (${HEAD_VERSION})"

echo "==> build the images from source and load them into kind"
docker build -q -t ghcr.io/zyvorai/netra:ci . >/dev/null
docker build -q -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:ci . >/dev/null
# The previous release's controller: its own source, built with HEAD's Dockerfile (an old
# Dockerfile may no longer build; the code and chart are what is under test).
mkdir -p "$W/old"
git archive "$PREVIOUS_TAG" | tar -x -C "$W/old"
cp Dockerfile "$W/old/Dockerfile"
docker build -q -t ghcr.io/zyvorai/netra:previous "$W/old" >/dev/null
for img in netra:ci netra-agent:ci netra:previous; do kind load docker-image "ghcr.io/zyvorai/$img" --name "$CLUSTER" >/dev/null; done
# A kind node is a container: unlike a real node (systemd mounts it) it has no bpffs, and
# the agent pins its maps under /sys/fs/bpf. Mount it, as an operator's node image would.
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf' || fail "could not mount bpffs on ${node}"
done

api_up() { # port-forward once; the forward follows the service, not a pod
  [[ -n "$PF" ]] && kill "$PF" 2>/dev/null || true
  kubectl -n "$NS" port-forward svc/netra 30870:30870 >"$W/pf.log" 2>&1 &
  PF=$!
  for _ in $(seq 1 40); do curl -ksf https://127.0.0.1:30870/healthz >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "the controller never answered through the port-forward"
}
api() { curl -ksf -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' "$@"; }
cfg() { api https://127.0.0.1:30870/api/v1/ebpf/config; }
ver() { curl -ksf https://127.0.0.1:30870/livez | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'; }
rolled() { kubectl -n "$NS" rollout status deploy/netra --timeout=300s >/dev/null || fail "the controller did not roll out"; }

echo "==> install the previous release's chart (persistent volume, no agent)"
mkdir -p "$W/oldchart"
git archive "$PREVIOUS_TAG" helm/netra | tar -x -C "$W/oldchart"
helm install netra "$W/oldchart/helm/netra" -n "$NS" --create-namespace \
  --set image.tag=previous --set image.pullPolicy=Never \
  --set auth.apiKey="$API_KEY" --set auth.agentKey="$AGENT_KEY" \
  --set agent.enabled=false --set persistence.enabled=true \
  --wait --timeout 5m >/dev/null || fail "the previous release did not install"
api_up
OLD_VER="$(ver)"; echo "    running ${OLD_VER}"
[[ "$OLD_VER" != "$HEAD_VERSION" ]] || fail "the 'previous' release reports the current version ${OLD_VER}: nothing is being upgraded"

echo "==> write state through the previous release's API"
api -X POST -d '{"ip":"203.0.113.41","direction":"egress"}' https://127.0.0.1:30870/api/v1/ebpf/deny >/dev/null
api -X POST -d '{"cidr":"198.51.100.0/24","direction":"egress"}' https://127.0.0.1:30870/api/v1/ebpf/cidr >/dev/null
api -X POST https://127.0.0.1:30870/api/v1/insights/baseline >/dev/null
BASELINE_AT="$(api https://127.0.0.1:30870/api/v1/insights/baseline | python3 -c 'import json,sys; print(json.load(sys.stdin)["baseline"]["capturedAt"])')"
cfg | grep -q 203.0.113.41 || fail "the rule was not accepted by the previous release"

state_intact() { # state_intact <what>
  cfg | python3 -c '
import json, sys
c = json.load(sys.stdin)
assert "203.0.113.41" in (c.get("blockedIPv4") or []), ("the deny rule is gone", c)
assert any(x["cidr"] == "198.51.100.0/24" for x in (c.get("blockedCidrs") or [])), ("the CIDR rule is gone", c)
assert c["mode"] == "observe", ("mode after a restart must be observe", c["mode"])' || fail "$1: state lost"
  [[ "$(api https://127.0.0.1:30870/api/v1/insights/baseline | python3 -c 'import json,sys; print(json.load(sys.stdin)["baseline"]["capturedAt"])')" == "$BASELINE_AT" ]] || fail "$1: the baseline changed"
}

echo "==> helm upgrade --reset-then-reuse-values to HEAD, agent DaemonSet enabled"
helm upgrade netra ./helm/netra -n "$NS" --reset-then-reuse-values \
  --set image.tag=ci --set image.pullPolicy=Never \
  --set agent.enabled=true --set agentImage.tag=ci --set agentImage.pullPolicy=Never \
  --wait --timeout 6m >/dev/null || fail "helm upgrade failed"
rolled; api_up
[[ "$(ver)" == "$HEAD_VERSION" ]] || fail "after the upgrade the controller reports $(ver), want ${HEAD_VERSION}"
state_intact "after the upgrade"
echo "==> the upgraded controller serves the whole UI (scripts, styles, logo, favicon)"
"$ROOT/scripts/check-served-ui.sh" https://127.0.0.1:30870 -k || fail "the upgraded controller serves an incomplete UI"
echo "    ${OLD_VER} -> ${HEAD_VERSION}: state and API key survived"

echo "==> the node agent starts, reports, and receives its configuration"
kubectl -n "$NS" rollout status ds/netra-agent --timeout=300s >/dev/null || fail "the agent DaemonSet did not become ready"
ok=0
for _ in $(seq 1 60); do
  if api https://127.0.0.1:30870/api/v1/agents | python3 -c 'import json,sys; d=json.load(sys.stdin)["items"]; sys.exit(0 if d and not d[0]["stale"] else 1)'; then ok=1; break; fi
  sleep 2
done
[[ "$ok" == 1 ]] || fail "no live agent report reached the controller"
api https://127.0.0.1:30870/api/v1/agents | python3 -c '
import json, sys
a = json.load(sys.stdin)["items"][0]
print("    agent %s: mode=%s hooks=%s" % (a["node"], a.get("mode"), a.get("hooks")))
assert a.get("mode") == "observe", ("a fresh agent must be in observe", a.get("mode"))'
# The default chart must not widen the agent's reach.
[[ "$(kubectl -n "$NS" get ds netra-agent -o jsonpath='{.spec.template.spec.hostPID}')" != "true" ]] || fail "hostPID is set on a default install"
kubectl -n "$NS" get ds netra-agent -o json | grep -q NETRA_TLS_UPROBES || fail "the agent env lacks NETRA_TLS_UPROBES"
kubectl -n "$NS" get ds netra-agent -o json | python3 -c '
import json, sys
env = {e["name"]: e.get("value") for c in json.load(sys.stdin)["spec"]["template"]["spec"]["containers"] for e in c.get("env", [])}
assert env.get("NETRA_TLS_UPROBES") == "off", env.get("NETRA_TLS_UPROBES")
assert env.get("NETRA_L7_SAMPLE") in (None, "off"), env.get("NETRA_L7_SAMPLE")' || fail "an opt-in sensor is on by default"

echo "==> deleting the controller pod: it returns with its state"
kubectl -n "$NS" delete pod -l app.kubernetes.io/name=netra --wait=true >/dev/null
rolled; api_up
state_intact "after a pod restart"
echo "    pod replaced; state intact"

echo "==> helm rollback returns to the previous release; its state is still readable"
helm rollback netra 1 -n "$NS" --wait --timeout 6m >/dev/null || fail "helm rollback failed"
rolled; api_up
[[ "$(ver)" == "$OLD_VER" ]] || fail "after the rollback the controller reports $(ver), want ${OLD_VER}"
state_intact "after the rollback"
echo "    rolled back to ${OLD_VER}; state readable by the older controller"

echo "==> PASS kind lifecycle (${OLD_VER} -> ${HEAD_VERSION} -> ${OLD_VER})"
