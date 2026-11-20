#!/usr/bin/env bash
# Netra — the plain manifests (no Helm) install and work on a real cluster (kind)
#
# `kubectl apply -k deploy/` plus the agent manifest, exactly the files the README tells
# an operator to apply, with only the image references pointed at locally built images.
# Asserts: the namespace, RBAC, volume and controller come up ready; the API enforces its
# key; the state volume is mounted and the controller reports persistence; the agent
# DaemonSet starts, reports, and starts in observe mode; no image tag in the manifests is
# stale (they must name the version this checkout builds).
#
# Needs a running kind cluster (CI: helm/kind-action), docker, kubectl.
#
# Usage:
#   ./scripts/ci-manifests-kind.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CLUSTER="${CLUSTER:-netra-ci}"
NS=netra-system
API_KEY="ci-man-api-key"
AGENT_KEY="ci-man-agent-key"
for c in docker kubectl kind curl python3; do command -v "$c" >/dev/null || { echo "missing required command: $c" >&2; exit 1; }; done
VERSION="$(sed -n 's/^const version = "\(.*\)"$/\1/p' cmd/netrad/main.go)"
PF=""
cleanup() { set +e; [[ -n "$PF" ]] && kill "$PF" 2>/dev/null; }
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  kubectl -n "$NS" get all,pvc,events -o wide 2>&1 | tail -30 >&2 || true
  kubectl -n "$NS" logs deploy/netra --tail=20 >&2 2>&1 || true
  kubectl -n "$NS" logs ds/netra-agent --tail=20 >&2 2>&1 || true
  exit 1
}

echo "==> the manifests name the version this checkout builds (${VERSION})"
grep -q "ghcr.io/zyvorai/netra:${VERSION}\$" deploy/controller.yaml || fail "deploy/controller.yaml does not reference netra:${VERSION}"
grep -q "ghcr.io/zyvorai/netra-agent:${VERSION}\$" deploy/agent.yaml || fail "deploy/agent.yaml does not reference netra-agent:${VERSION}"

echo "==> build the images and load them into kind; mount bpffs on the node"
docker build -q -t "ghcr.io/zyvorai/netra:${VERSION}" . >/dev/null
docker build -q -f Dockerfile.agent -t "ghcr.io/zyvorai/netra-agent:${VERSION}" . >/dev/null
for img in "netra:${VERSION}" "netra-agent:${VERSION}"; do kind load docker-image "ghcr.io/zyvorai/${img}" --name "$CLUSTER" >/dev/null; done
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf' || fail "could not mount bpffs on ${node}"
done

echo "==> kubectl apply -k deploy/ (the documented path), then the agent manifest"
kubectl apply -f deploy/namespace.yaml >/dev/null
kubectl -n "$NS" create secret generic netra-auth --from-literal=api-key="$API_KEY" --from-literal=agent-key="$AGENT_KEY" >/dev/null
kubectl apply -k deploy/ >/dev/null || fail "kubectl apply -k deploy/ failed"
kubectl apply -f deploy/agent.yaml >/dev/null || fail "kubectl apply -f deploy/agent.yaml failed"
kubectl -n "$NS" rollout status deploy/netra --timeout=300s >/dev/null || fail "the controller did not become ready"
kubectl -n "$NS" rollout status ds/netra-agent --timeout=300s >/dev/null || fail "the agent DaemonSet did not become ready"

kubectl -n "$NS" port-forward svc/netra 30870:30870 >/dev/null 2>&1 &
PF=$!
for _ in $(seq 1 40); do curl -ksf https://127.0.0.1:30870/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -ksf https://127.0.0.1:30870/healthz >/dev/null || fail "the controller does not answer /healthz"

echo "==> the API enforces its key and reports the right version"
code="$(curl -ks -o /dev/null -w '%{http_code}' https://127.0.0.1:30870/api/v1/status)"
[[ "$code" == 401 ]] || fail "an unauthenticated /api/v1/status returned ${code}, want 401"
curl -ksf -H "Authorization: Bearer ${API_KEY}" https://127.0.0.1:30870/api/v1/status >/dev/null || fail "the API key from the Secret is not accepted"
[[ "$(curl -ksf https://127.0.0.1:30870/livez | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')" == "$VERSION" ]] || fail "the controller reports the wrong version"

echo "==> the state volume is mounted and used"
kubectl -n "$NS" get pvc netra-state -o jsonpath='{.status.phase}' | grep -qx Bound || fail "the state volume is not bound"
curl -ksf -X POST -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' -d '{"ip":"203.0.113.71","direction":"egress"}' https://127.0.0.1:30870/api/v1/ebpf/deny >/dev/null
kubectl -n "$NS" delete pod -l app.kubernetes.io/name=netra --wait=true >/dev/null
kubectl -n "$NS" rollout status deploy/netra --timeout=300s >/dev/null || fail "the controller did not come back"
kill "$PF" 2>/dev/null || true
kubectl -n "$NS" port-forward svc/netra 30870:30870 >/dev/null 2>&1 &
PF=$!
for _ in $(seq 1 40); do curl -ksf https://127.0.0.1:30870/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -ksf -H "Authorization: Bearer ${API_KEY}" https://127.0.0.1:30870/api/v1/ebpf/config | grep -q 203.0.113.71 || fail "the rule did not survive a pod restart: the state volume is not in use"
echo "    a rule written before the pod was replaced is still there"

echo "==> the agent reports and starts in observe"
ok=0
for _ in $(seq 1 60); do
  if curl -ksf -H "Authorization: Bearer ${API_KEY}" https://127.0.0.1:30870/api/v1/agents | python3 -c 'import json,sys; d=json.load(sys.stdin)["items"]; sys.exit(0 if d and not d[0]["stale"] and d[0].get("mode")=="observe" else 1)'; then ok=1; break; fi
  sleep 2
done
[[ "$ok" == 1 ]] || fail "no live agent in observe mode reached the controller"
echo "    agent reporting, observe mode"

echo "==> PASS manifests kind"
