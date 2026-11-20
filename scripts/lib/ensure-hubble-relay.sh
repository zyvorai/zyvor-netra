#!/usr/bin/env bash
# Ensure Cilium Hubble Relay is available (required for Netra live flows).
# Safe to run repeatedly. Adapted from PacketWolf's ensure-hubble-relay.sh.
set -euo pipefail

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

kubectl_cmd() {
  local sys_k3s="/etc/rancher/k3s/k3s.yaml"
  if [[ -z "${KUBECONFIG:-}" || ! -r "${KUBECONFIG}" ]]; then
    if [[ -f "$sys_k3s" ]]; then
      if [[ -r "$sys_k3s" ]]; then
        export KUBECONFIG="$sys_k3s"
      else
        mkdir -p "$HOME/.kube"
        local kcfg="$HOME/.kube/netra-k3s.yaml"
        # shellcheck disable=SC2024 # only the read needs root; the copy belongs in the caller's own $HOME
        sudo cat "$sys_k3s" > "$kcfg"
        chmod 600 "$kcfg"
        export KUBECONFIG="$kcfg"
      fi
    fi
  fi
  if [[ -x /usr/local/bin/kubectl ]]; then
    /usr/local/bin/kubectl "$@"
    return $?
  fi
  if command -v k3s >/dev/null 2>&1 && ! command -v kubectl >/dev/null 2>&1; then
    k3s kubectl "$@"
    return $?
  fi
  kubectl "$@"
}

hubble_relay_ready() {
  kubectl_cmd get deploy -n kube-system hubble-relay &>/dev/null \
    && kubectl_cmd -n kube-system wait --for=condition=available deploy/hubble-relay --timeout=5s &>/dev/null
}

patch_gatewayclass_for_helm() {
  if ! kubectl_cmd get gatewayclass cilium &>/dev/null; then
    return 0
  fi
  local managed
  managed="$(kubectl_cmd get gatewayclass cilium -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}' 2>/dev/null || true)"
  if [[ "$managed" == "Helm" ]]; then
    return 0
  fi
  echo "  Patching GatewayClass cilium for Helm ownership..."
  kubectl_cmd label gatewayclass cilium app.kubernetes.io/managed-by=Helm --overwrite
  kubectl_cmd annotate gatewayclass cilium \
    meta.helm.sh/release-name=cilium \
    meta.helm.sh/release-namespace=kube-system \
    --overwrite
}

if hubble_relay_ready; then
  echo "Hubble Relay already available"
  exit 0
fi

if ! kubectl_cmd get daemonset -n kube-system cilium &>/dev/null; then
  echo "Cilium DaemonSet not found; install Cilium before Netra" >&2
  exit 1
fi

patch_gatewayclass_for_helm

if command -v cilium >/dev/null 2>&1; then
  echo "Enabling Hubble Relay via cilium CLI..."
  # May fail on validate templates; Helm path below is authoritative.
  cilium hubble enable --relay 2>/dev/null || true
fi

if ! hubble_relay_ready && command -v helm >/dev/null 2>&1; then
  echo "Enabling Hubble Relay via Helm upgrade..."
  helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
  helm repo update cilium 2>/dev/null || true
  chart_version="$(helm list -n kube-system -o json 2>/dev/null | python3 -c 'import json,sys
try:
  rels=json.load(sys.stdin)
except Exception:
  sys.exit(1)
for r in rels:
  if r.get("name")=="cilium":
    print(r["chart"].split("-")[-1]); sys.exit(0)
sys.exit(1)' 2>/dev/null || echo 1.20.0)"
  patch_gatewayclass_for_helm
  helm upgrade cilium cilium/cilium --version "$chart_version" --namespace kube-system \
    --reuse-values \
    --set hubble.enabled=true \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=false \
    --wait --timeout 300s
fi

kubectl_cmd -n kube-system wait --for=condition=available deploy/hubble-relay --timeout=180s
echo "Hubble Relay ready"
