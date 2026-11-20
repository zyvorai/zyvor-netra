#!/usr/bin/env bash
# Netra — controller high availability with two real replicas (kind)
#
# Needs a running kind cluster (CI: helm/kind-action), docker, helm, kubectl. Installs
# the chart from this checkout with replicaCount=2, ha.enabled=true and a shared
# ReadWriteMany volume (a hostPath PV, valid on a one-node kind cluster: both replicas
# see the same directory and the same flock). Asserts, on the real cluster:
#
#   election   exactly one replica is Ready and holds the Lease; the other is running but
#              unready, and refuses API calls (while still answering /healthz), and this
#              never flips to two Ready replicas at any sample
#   failover   killing the leader without warning promotes the standby within the lease
#              window; a graceful delete promotes it faster (the Lease is released); the
#              rules written before the failover are served by the new leader (shared
#              state), and the killed pod comes back as the new standby
#   safety     an enforcement lease is not carried across a leader change (mode observe)
#
# Usage:
#   ./scripts/ci-ha-kind.sh                # cluster netra-ci
#   CLUSTER=mine ./scripts/ci-ha-kind.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLUSTER="${CLUSTER:-netra-ci}"
NS=netra-system
API_KEY="ci-ha-api-key"
AGENT_KEY="ci-ha-agent-key"
for c in docker helm kubectl kind curl python3; do command -v "$c" >/dev/null || { echo "missing required command: $c" >&2; exit 1; }; done
PFS=()
cleanup() { set +e; for p in "${PFS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

dump() {
  kubectl -n "$NS" get pods,lease,pvc -o wide 2>&1 | tail -20 >&2 || true
  for p in $(kubectl -n "$NS" get pods -l app.kubernetes.io/name=netra -o name 2>/dev/null); do echo "--- $p" >&2; kubectl -n "$NS" logs "$p" --tail=20 >&2 2>&1 || true; done
}
fail() { echo "FAIL: $*" >&2; dump; exit 1; }

echo "==> build the controller image and load it into kind"
docker build -q -t ghcr.io/zyvorai/netra:ci . >/dev/null
kind load docker-image ghcr.io/zyvorai/netra:ci --name "$CLUSTER" >/dev/null

echo "==> a shared ReadWriteMany volume (hostPath on the one kind node)"
# The controller runs as a non-root user and kubelet creates a hostPath directory as root
# (0755), so the state lock could not be created. A real RWX filesystem is provisioned
# writable for the pod's user; do the equivalent on the node.
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" sh -c 'mkdir -p /var/lib/netra-ha && chmod 0777 /var/lib/netra-ha' || fail "could not prepare the shared directory on ${node}"
done
kubectl create namespace "$NS" >/dev/null 2>&1 || true
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolume
metadata: {name: netra-ha-state}
spec:
  capacity: {storage: 1Gi}
  accessModes: [ReadWriteMany]
  storageClassName: ""
  persistentVolumeReclaimPolicy: Delete
  hostPath: {path: /var/lib/netra-ha, type: DirectoryOrCreate}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: netra-ha-state, namespace: ${NS}}
spec:
  accessModes: [ReadWriteMany]
  storageClassName: ""
  volumeName: netra-ha-state
  resources: {requests: {storage: 1Gi}}
EOF

echo "==> helm install: 2 replicas, ha.enabled, the shared volume"
# The chart's own guard rails are part of the contract: HA on a ReadWriteOnce chart-managed
# volume must be refused (checked in the helm job); here it is the valid configuration.
helm install netra ./helm/netra -n "$NS" \
  --set image.tag=ci --set image.pullPolicy=Never \
  --set auth.apiKey="$API_KEY" --set auth.agentKey="$AGENT_KEY" \
  --set agent.enabled=false --set replicaCount=2 --set ha.enabled=true \
  --set persistence.enabled=true --set persistence.existingClaim=netra-ha-state \
  --set ha.podDisruptionBudget.enabled=false \
  --timeout 5m >/dev/null || fail "helm install failed"

pods() { kubectl -n "$NS" get pods -l app.kubernetes.io/name=netra -o json; }
# ready_pods: names of pods whose Ready condition is True (one per line)
ready_pods() {
  pods | python3 -c '
import json, sys
for p in json.load(sys.stdin)["items"]:
    if p["metadata"].get("deletionTimestamp"): continue
    if any(c["type"] == "Ready" and c["status"] == "True" for c in p["status"].get("conditions", [])): print(p["metadata"]["name"])'
}
all_pods() {
  pods | python3 -c '
import json, sys
for p in json.load(sys.stdin)["items"]:
    if not p["metadata"].get("deletionTimestamp"): print(p["metadata"]["name"], p["status"].get("phase"))'
}
holder() { kubectl -n "$NS" get lease netra-controller -o jsonpath='{.spec.holderIdentity}' 2>/dev/null; }

echo "==> exactly one leader: one Ready pod, and it holds the Lease"
leader=""
for _ in $(seq 1 90); do
  n="$(ready_pods | wc -l | tr -d ' ')"
  total="$(all_pods | wc -l | tr -d ' ')"
  if [[ "$n" == 1 && "$total" == 2 ]]; then leader="$(ready_pods)"; break; fi
  sleep 2
done
[[ -n "$leader" ]] || fail "never reached one Ready leader and one standby"
standby="$(all_pods | awk '{print $1}' | grep -vx "$leader")"
[[ "$(holder)" == *"$leader"* ]] || fail "the Ready pod ${leader} does not hold the Lease (holder: $(holder))"
echo "    leader ${leader}, standby ${standby}, lease held by $(holder)"

echo "==> the standby refuses API calls but is alive"
kubectl -n "$NS" port-forward "pod/${standby}" 30871:30870 >/dev/null 2>&1 &
PFS+=($!)
for _ in $(seq 1 30); do curl -ksf https://127.0.0.1:30871/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -ksf https://127.0.0.1:30871/healthz >/dev/null || fail "the standby does not answer /healthz"
code="$(curl -ks -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${API_KEY}" https://127.0.0.1:30871/api/v1/ebpf/config)"
[[ "$code" == 503 ]] || fail "the standby served an API call (HTTP ${code}), want 503"
echo "    standby: /healthz 200, API 503"

echo "==> never two Ready replicas (60 s of sampling)"
for _ in $(seq 1 30); do
  n="$(ready_pods | wc -l | tr -d ' ')"
  [[ "$n" -le 1 ]] || fail "two replicas were Ready at once"
  sleep 2
done
echo "    at most one Ready at every sample"

kubectl -n "$NS" port-forward svc/netra 30870:30870 >/dev/null 2>&1 &
PFS+=($!)
api() { curl -ksf -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' "$@"; }
repoint() { # the forward is tied to a pod; after a failover open a new one
  kill "${PFS[-1]}" 2>/dev/null || true
  kubectl -n "$NS" port-forward svc/netra 30870:30870 >/dev/null 2>&1 &
  PFS+=($!)
  for _ in $(seq 1 40); do curl -ksf https://127.0.0.1:30870/healthz >/dev/null 2>&1 && return 0; sleep 1; done
  fail "the service never answered after the failover"
}
for _ in $(seq 1 30); do curl -ksf https://127.0.0.1:30870/healthz >/dev/null 2>&1 && break; sleep 1; done
api -X POST -d '{"ip":"203.0.113.61","direction":"egress"}' https://127.0.0.1:30870/api/v1/ebpf/deny >/dev/null || fail "could not write a rule through the leader"
api -X PUT -d '{"mode":"enforce"}' "https://127.0.0.1:30870/api/v1/ebpf/mode?lease=10m" >/dev/null || fail "could not enter enforce through the leader"

failover() { # failover <label> <kubectl delete args...> <max seconds>
  local label="$1" max="$2"; shift 2
  local old="$leader" start now new=""
  start="$(date +%s)"
  kubectl -n "$NS" delete pod "$old" "$@" >/dev/null
  while :; do
    now="$(date +%s)"
    new="$(ready_pods | grep -vx "$old" | head -1 || true)"
    [[ -n "$new" ]] && break
    (( now - start < max )) || fail "${label}: no replica took over within ${max}s"
    sleep 1
  done
  echo "    ${label}: ${new} took over in $(( $(date +%s) - start )) s (limit ${max} s)"
  leader="$new"
  repoint
  api https://127.0.0.1:30870/api/v1/ebpf/config | python3 -c '
import json, sys
c = json.load(sys.stdin)
assert "203.0.113.61" in (c.get("blockedIPv4") or []), ("the rule written before the failover is gone", c)
assert c["mode"] == "observe", ("an enforcement lease was carried across a leader change", c["mode"])' || fail "${label}: state after the failover"
  # the replaced pod becomes the new standby
  for _ in $(seq 1 90); do
    [[ "$(all_pods | wc -l | tr -d ' ')" == 2 && "$(ready_pods | wc -l | tr -d ' ')" == 1 ]] && break
    sleep 2
  done
  [[ "$(ready_pods | wc -l | tr -d ' ')" == 1 && "$(all_pods | wc -l | tr -d ' ')" == 2 ]] || fail "${label}: the cluster did not settle at one leader and one standby"
  [[ "$(holder)" == *"$leader"* ]] || fail "${label}: the Lease is not held by the Ready pod"
}

echo "==> the leader is killed without warning (no Lease release)"
failover "crash failover" 60 --grace-period=0 --force
api -X PUT -d '{"mode":"enforce"}' "https://127.0.0.1:30870/api/v1/ebpf/mode?lease=10m" >/dev/null || fail "could not re-enter enforce on the new leader"

echo "==> the leader is deleted gracefully (the Lease is released, so it is faster)"
failover "graceful failover" 45

echo "==> PASS ha kind"
