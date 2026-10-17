#!/usr/bin/env bash
# Bootstrap K3s (CNI-less) + Cilium 1.20 with Hubble Relay for Netra.
# Idempotent. Pattern mirrors PacketWolf remote K3s bootstrap.
set -euo pipefail

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

if ! command -v k3s >/dev/null 2>&1; then
  echo "Installing K3s without flannel/kube-proxy (Cilium will own networking)..."
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable=traefik --flannel-backend=none --disable-network-policy --disable-kube-proxy" sh -
fi

# Binary present but unit missing/stopped (partial uninstall, host reuse).
if ! systemctl is-active --quiet k3s 2>/dev/null; then
  echo "Starting K3s..."
  if [[ ! -f /etc/systemd/system/k3s.service ]]; then
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable=traefik --flannel-backend=none --disable-network-policy --disable-kube-proxy" sh -
  else
    sudo systemctl enable --now k3s
  fi
  for _ in $(seq 1 60); do
    if k3s kubectl get --raw=/readyz >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
fi

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
if [[ ! -r "$KUBECONFIG" ]]; then
  mkdir -p "$HOME/.kube"
  # shellcheck disable=SC2024 # only the read needs root; the copy belongs in the caller's own $HOME
  sudo cat /etc/rancher/k3s/k3s.yaml > "$HOME/.kube/netra-k3s.yaml"
  chmod 600 "$HOME/.kube/netra-k3s.yaml"
  export KUBECONFIG="$HOME/.kube/netra-k3s.yaml"
fi

kubectl_bin() {
  if command -v kubectl >/dev/null 2>&1; then
    kubectl "$@"
  else
    k3s kubectl "$@"
  fi
}

if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# Point Cilium at the host apiserver before ClusterIP works. On some lab
# networks 10.43.0.0/16 is routed to the LAN gateway, so hitting
# https://10.43.0.1:443 returns a foreign cert (x509 unknown authority).
HOST_IP="$(hostname -I | awk '{print $1}')"
CILIUM_API_SETS=(
  --set "k8sServiceHost=${HOST_IP}"
  --set k8sServicePort=6443
)

if ! kubectl_bin get daemonset -n kube-system cilium &>/dev/null; then
  echo "Installing Cilium 1.20.0 with Hubble Relay..."
  helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
  helm repo update cilium 2>/dev/null || true
  helm install cilium cilium/cilium --version 1.20.0 --namespace kube-system \
    "${CILIUM_API_SETS[@]}" \
    --set operator.replicas=1 \
    --set kubeProxyReplacement=true \
    --set hubble.enabled=true \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=false \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}" \
    --wait --timeout 300s
else
  # Repair installs that landed without host API (chicken-and-egg / route leak).
  cur_host="$(kubectl_bin -n kube-system get cm cilium-config -o jsonpath='{.data.k8s-service-host}' 2>/dev/null || true)"
  if [[ -z "$cur_host" || "$cur_host" == "10.43.0.1" ]]; then
    echo "Updating Cilium to use host apiserver ${HOST_IP}:6443..."
    helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
    helm upgrade cilium cilium/cilium --version 1.20.0 --namespace kube-system \
      --reuse-values \
      "${CILIUM_API_SETS[@]}" \
      --wait --timeout 300s
  fi
fi

kubectl_bin -n kube-system rollout status ds/cilium --timeout=300s || true
echo "K3s + Cilium baseline ready"
