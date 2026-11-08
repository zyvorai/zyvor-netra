#!/usr/bin/env bash
# Netra — remote deploy (SSH + rsync + optional K3s/Cilium/Hubble + Helm)
#
# Profiles:
#   default / --k3s   Bootstrap K3s + Cilium 1.20 + Hubble Relay if needed, then Helm
#   --k8s             Helm on an existing kubeconfig (cluster already has Cilium)
#   --quick           Sync + Helm only (images must already exist on the host)
#
# Usage:
#   ./scripts/deploy-remote.sh user@10.0.1.5
#   ./scripts/deploy-remote.sh user@10.0.1.5 --k8s
#   ./scripts/deploy-container.sh user@10.0.1.5
#
# NETRA_REMOTE_SUBDIR overrides where the remote checkout lives, relative to
# the target user's $HOME (default: .deployments/netra). Set it to a path
# outside .deployments/ on hosts that also run other projects' deploy
# scripts syncing into that shared parent with `rsync --delete` — a
# sibling project's delete-sync can otherwise wipe netra's checkout mid-run.
#
# Deploy guards (scripts/lib/deploy-guards.sh): the images are imported into k3s under
# a fixed tag, and kubelet's image GC (disk above 85%) can remove one before its pod
# starts, leaving the controller in ImagePullBackOff with helm reporting success.
# The deploy warns at NETRA_DEPLOY_WARN_DISK_PCT (default 80) and refuses at
# NETRA_DEPLOY_MAX_DISK_PCT (default 95); NETRA_DEPLOY_SKIP_DISK_CHECK=1 overrides.
# It re-imports a missing image and waits for each rollout to COMPLETE
# (NETRA_DEPLOY_READY_TIMEOUT, default 600 s) instead of trusting helm; a Ready pod is
# not enough, because right after the restart the old pod is still Ready.
#
# Netra runs on top of Cilium; it does not replace the CNI.
# UI/API default NodePort/host access: :30870
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="k3s"
DRY_RUN=false
VERIFY_ONLY=false
TARGET=""
# shellcheck disable=SC2034 # assigned for callers that source this file; not read here
TARGET_USER=""
POSITIONAL=()
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)

usage() {
  sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --k3s) PROFILE="k3s"; shift ;;
    --k8s) PROFILE="k8s"; shift ;;
    --quick) PROFILE="quick"; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    -*)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -eq 1 ]]; then
  TARGET="${POSITIONAL[0]}"
elif [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  # ./scripts/deploy-remote.sh HOST USER
  if [[ "${POSITIONAL[0]}" == *@* ]]; then
    TARGET="${POSITIONAL[0]}"
  elif [[ "${POSITIONAL[1]}" == *@* ]]; then
    TARGET="${POSITIONAL[1]}"
  else
    TARGET="${POSITIONAL[1]}@${POSITIONAL[0]}"
  fi
elif [[ ${#POSITIONAL[@]} -gt 2 ]]; then
  echo "usage: $0 user@host [--k8s]   or   $0 HOST USER [--k8s]" >&2
  exit 2
fi

if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 user@host [--k3s|--k8s|--quick]" >&2
  echo "   or: $0 HOST USER [--k8s]" >&2
  exit 2
fi

ALLOW_UNAUTH_LOCAL="${NETRA_ALLOW_UNAUTHENTICATED:-false}"
# No well-known default: a published admin key on a reachable NodePort is an open door.
# Unless NETRA_API_KEY is set, mint a random one. It is written to ~/.netra/api-key on the host;
# sign in to the dashboard as admin with that key as the password (the UI probes /api/v1/fleet).
API_KEY_LOCAL="${NETRA_API_KEY:-$(openssl rand -hex 24)}"
AGENT_KEY_LOCAL="${NETRA_AGENT_KEY:-$(openssl rand -hex 32)}"
# Node agent is required for dashboard data. Default on for k3s/k8s deploys;
# --quick and explicit NETRA_AGENT_ENABLED=false leave it off.
if [[ -n "${NETRA_AGENT_ENABLED:-}" ]]; then
  AGENT_ENABLED_LOCAL="${NETRA_AGENT_ENABLED}"
elif [[ "$PROFILE" == "quick" ]]; then
  AGENT_ENABLED_LOCAL=false
else
  AGENT_ENABLED_LOCAL=true
fi
WORKLOAD_CONSOLE_ENABLED_LOCAL="${NETRA_WORKLOAD_CONSOLE_ENABLED:-false}"
AGENT_INTERFACES_LOCAL="${NETRA_AGENT_INTERFACES:-}"
AGENT_XDP_INTERFACES_LOCAL="${NETRA_AGENT_XDP_INTERFACES:-}"

ssh_host() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
REMOTE_HOME="$(ssh_host 'printf %s "$HOME"')"
REMOTE_DIR="${REMOTE_HOME}/${NETRA_REMOTE_SUBDIR:-.deployments/netra}"

log() { printf '[netra-deploy] %s\n' "$*"; }

if $VERIFY_ONLY; then
  ssh_host 'bash -s' <<'EOF'
set -euo pipefail
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/netra-k3s.yaml}"
if [[ ! -r "${KUBECONFIG}" ]]; then
  mkdir -p "$HOME/.kube"
  sudo cat /etc/rancher/k3s/k3s.yaml | sed "s/127.0.0.1/$(hostname -I | awk '{print $1}')/" > "$HOME/.kube/netra-k3s.yaml"
  chmod 600 "$HOME/.kube/netra-k3s.yaml"
  export KUBECONFIG="$HOME/.kube/netra-k3s.yaml"
fi
kubectl -n netra-system get deploy,svc,pods
kubectl -n kube-system get deploy hubble-relay 2>/dev/null || true
curl -skf https://127.0.0.1:30870/healthz
EOF
  exit 0
fi

log "sync → ${TARGET}:${REMOTE_DIR}"
if ! $DRY_RUN; then
  ssh_host "mkdir -p ${REMOTE_DIR}"
  rsync -az --delete \
    --exclude '.git' --exclude 'bin' --exclude 'web/node_modules' --exclude 'web/dist' \
    --exclude 'bpf/*.o' --exclude '.DS_Store' --exclude '.cursor' \
    "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"
fi

remote_script=$(cat <<EOF
set -euo pipefail
cd ${REMOTE_DIR}
export PATH="/usr/local/bin:\$HOME/go/bin:/usr/bin:\$PATH"
PROFILE="${PROFILE}"

mkdir -p "\$HOME/.kube"
if [[ ! -r "\$HOME/.kube/netra-k3s.yaml" ]] || [[ /etc/rancher/k3s/k3s.yaml -nt "\$HOME/.kube/netra-k3s.yaml" ]]; then
  sudo cat /etc/rancher/k3s/k3s.yaml > "\$HOME/.kube/netra-k3s.yaml"
  chmod 600 "\$HOME/.kube/netra-k3s.yaml"
fi
export KUBECONFIG="\$HOME/.kube/netra-k3s.yaml"

# The images are built here and imported into containerd under a fixed tag, so
# kubelet's image GC can remove one between the import and its pod starting (the
# disk near 85%). These guards say so up front, re-import a missing image, and wait
# for the pods to be Ready instead of trusting helm (scripts/lib/deploy-guards.sh).
source scripts/lib/deploy-guards.sh
CONTROLLER_IMAGE="ghcr.io/zyvorai/netra:0.27.81"
AGENT_IMAGE="ghcr.io/zyvorai/netra-agent:0.27.81"
deploy_disk_guard /

if [[ "\$PROFILE" == "k3s" ]]; then
  bash scripts/lib/ensure-cilium-k3s.sh
fi
bash scripts/lib/ensure-hubble-relay.sh

ALLOW_UNAUTH="${ALLOW_UNAUTH_LOCAL}"
API_KEY="${API_KEY_LOCAL}"
AGENT_KEY="${AGENT_KEY_LOCAL}"
AGENT_ENABLED="${AGENT_ENABLED_LOCAL}"
WORKLOAD_CONSOLE_ENABLED="${WORKLOAD_CONSOLE_ENABLED_LOCAL}"
AGENT_INTERFACES="${AGENT_INTERFACES_LOCAL}"
AGENT_XDP_INTERFACES="${AGENT_XDP_INTERFACES_LOCAL}"
mkdir -p "\$HOME/.netra"
printf '%s\n' "\$API_KEY" > "\$HOME/.netra/api-key"
printf '%s\n' "\$AGENT_KEY" > "\$HOME/.netra/agent-key"
HOST_IP="\$(hostname -I | awk '{print \$1}')"
cat > "\$HOME/.netra/env" <<ENVEOF
# Written by deploy-remote.sh — sourced automatically by netractl.
NETRA_URL=https://\${HOST_IP}:30870
NETRA_TLS_INSECURE=true
NETRA_API_KEY=\${API_KEY}
ENVEOF
# Also keep a loopback-friendly default for local curls.
grep -q 'NETRA_TLS_INSECURE' "\$HOME/.netra/env"
chmod 600 "\$HOME/.netra/"* || true

export GOTOOLCHAIN=auto
export PATH="/usr/local/go/bin:\$PATH"

build_image() {
  # Prefer host Go + npm then a thin runtime image.
  local runtime=""
  if command -v podman >/dev/null 2>&1; then
    runtime=podman
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    runtime=docker
  fi
  if command -v go >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    echo "Building Netra on host with \$(go version) (GOTOOLCHAIN=\$GOTOOLCHAIN)..."
    npm --prefix web install
    npm --prefix web run build
    mkdir -p bin
    CGO_ENABLED=0 go build -o bin/netrad ./cmd/netrad
    CGO_ENABLED=0 go build -o bin/netractl ./cmd/netractl
    # Put netractl on PATH for operators (same as make install).
    if install -d /usr/local/bin 2>/dev/null && install -m 755 bin/netractl /usr/local/bin/netractl 2>/dev/null; then
      echo "Installed netractl → /usr/local/bin/netractl"
    elif sudo install -d /usr/local/bin && sudo install -m 755 bin/netractl /usr/local/bin/netractl; then
      echo "Installed netractl → /usr/local/bin/netractl (via sudo)"
    else
      mkdir -p "\$HOME/.local/bin"
      install -m 755 bin/netractl "\$HOME/.local/bin/netractl"
      echo "Installed netractl → \$HOME/.local/bin/netractl (add to PATH if needed)"
    fi
    if [[ -z "\$runtime" ]]; then
      echo "podman or working docker required to build controller image" >&2
      exit 1
    fi
    \$runtime build -f Dockerfile.runtime -t ghcr.io/zyvorai/netra:0.27.81 .
    return 0
  fi
  if [[ -z "\$runtime" ]]; then
    echo "podman or working docker required to build controller image" >&2
    exit 1
  fi
  \$runtime build -t ghcr.io/zyvorai/netra:0.27.81 .
}

import_image() {
  if command -v podman >/dev/null 2>&1; then
    podman save ghcr.io/zyvorai/netra:0.27.81 | sudo k3s ctr images import -
  else
    docker save ghcr.io/zyvorai/netra:0.27.81 | sudo k3s ctr images import -
  fi
}

# Builds the privileged node agent from Dockerfile.agent (compiles both the
# Go binary and bpf/netra_tc.c inside the image, same as CI's compile check)
# and imports it the same way as the controller image above. Only invoked
# when AGENT_ENABLED=true (Helm/deploy default). Opt out with
# NETRA_AGENT_ENABLED=false for controller-only installs.
build_agent_image() {
  local runtime=""
  if command -v podman >/dev/null 2>&1; then
    runtime=podman
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    runtime=docker
  fi
  if [[ -z "\$runtime" ]]; then
    echo "podman or working docker required to build the agent image" >&2
    exit 1
  fi
  echo "Building netra-agent (Go binary + BPF object) via Dockerfile.agent..."
  \$runtime build -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:0.27.81 .
}

import_agent_image() {
  if command -v podman >/dev/null 2>&1; then
    podman save ghcr.io/zyvorai/netra-agent:0.27.81 | sudo k3s ctr images import -
  else
    docker save ghcr.io/zyvorai/netra-agent:0.27.81 | sudo k3s ctr images import -
  fi
}

if [[ "\$PROFILE" != "quick" ]]; then
  # Build both, then import both: an imported image no pod uses yet is exactly what
  # kubelet's image GC collects, and the second build is what pushes the disk toward
  # its threshold, so importing the controller image first left it exposed for the
  # whole agent build.
  build_image
  if [[ "\$AGENT_ENABLED" == "true" ]]; then
    build_agent_image
  fi
  import_image
  if [[ "\$AGENT_ENABLED" == "true" ]]; then
    import_agent_image
  fi
fi

HELM_AUTH=(--set "auth.apiKey=\$API_KEY" --set "auth.agentKey=\$AGENT_KEY")
if [[ "\$ALLOW_UNAUTH" == "true" ]]; then
  HELM_AUTH=(--set auth.allowUnauthenticated=true --set auth.apiKey="" --set auth.agentKey="")
fi

AGENT_SET=(--set agent.enabled=false)
if [[ "\$AGENT_ENABLED" == "true" ]]; then
  AGENT_SET=(--set agent.enabled=true --set agentImage.repository=ghcr.io/zyvorai/netra-agent --set agentImage.tag=0.27.81 --set agentImage.pullPolicy=IfNotPresent)
fi

CONSOLE_SET=(--set workloadConsole.enabled=false)
if [[ "\$WORKLOAD_CONSOLE_ENABLED" == "true" ]]; then
  CONSOLE_SET=(--set workloadConsole.enabled=true)
fi

IFACE_SET=()
if [[ -n "\$AGENT_INTERFACES" ]]; then
  IFACE_SET+=(--set "agent.interfaces=\$AGENT_INTERFACES")
fi
if [[ -n "\$AGENT_XDP_INTERFACES" ]]; then
  IFACE_SET+=(--set "agent.xdpInterfaces=\$AGENT_XDP_INTERFACES")
fi

# Serve one self-signed cert across controller restarts so API clients can pin it
# (the chart otherwise mints a new one per pod). NETRA_TLS_PERSIST=0 opts out.
TLS_SET=()
if [[ "${NETRA_TLS_PERSIST:-1}" != "0" ]]; then
  kubectl create namespace netra-system --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  if ! kubectl -n netra-system get secret netra-tls >/dev/null 2>&1; then
    tls_dir="\$(mktemp -d)"
    openssl req -x509 -nodes -days 3650 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "\$tls_dir/tls.key" -out "\$tls_dir/tls.crt" -subj "/CN=netra/O=Zyvor AI Labs" \
      -addext "subjectAltName=DNS:netra,DNS:netra.netra-system.svc,DNS:localhost,IP:127.0.0.1,IP:\$HOST_IP" 2>/dev/null
    kubectl -n netra-system create secret tls netra-tls --cert="\$tls_dir/tls.crt" --key="\$tls_dir/tls.key" >/dev/null
    rm -rf "\$tls_dir"
  fi
  kubectl -n netra-system get secret netra-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "\$HOME/.netra/tls.crt"
  chmod 600 "\$HOME/.netra/tls.crt"
  TLS_SET=(--set tls.existingSecret=netra-tls)
fi

deploy_ensure_image "\$CONTROLLER_IMAGE"
if [[ "\$AGENT_ENABLED" == "true" ]]; then
  deploy_ensure_image "\$AGENT_IMAGE"
fi

helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  "\${HELM_AUTH[@]}" \
  "\${AGENT_SET[@]}" \
  "\${CONSOLE_SET[@]}" \
  "\${IFACE_SET[@]}" \
  "\${TLS_SET[@]}" \
  --set image.repository=ghcr.io/zyvorai/netra \
  --set image.tag=0.27.81 \
  --set image.pullPolicy=IfNotPresent \
  --set hubble.address=hubble-relay.kube-system.svc:80 \
  --set service.type=NodePort \
  --set service.port=30870 \
  --set service.nodePort=30870 \
  --set cilium.enabled=true \
  --set hubble.enabled=true \
  --wait --timeout 300s

# image.tag is a fixed value ("0.27.81"), not a per-build digest/tag, so the
# Deployment's pod template never actually changes between runs even though
# the image content underneath that tag does (a fresh image was just built
# and imported above). With imagePullPolicy=IfNotPresent, Kubernetes has no
# signal to replace the already-running pod in that case — "helm upgrade"
# and "rollout status" both report success trivially because there is no
# diff to roll out, and the old pod keeps serving the old image indefinitely.
# Force a real restart every run so the freshly imported image is always
# what ends up running, not just what's sitting in the local image store.
deploy_ensure_image "\$CONTROLLER_IMAGE"
kubectl -n netra-system rollout restart deployment/netra
# Not "rollout status --timeout=180s": on a loaded host that timed out and aborted
# the script before the agent restart, and it cannot tell a slow rollout from a pod
# stuck in ImagePullBackOff. This waits for the rollout to complete (not just for a
# Ready pod: right after the restart the OLD pod is still Ready), repairs a missing
# image, and fails loudly (with the pods printed) if the controller does not come up.
deploy_wait_ready deployment/netra "app.kubernetes.io/name=netra" "\$CONTROLLER_IMAGE"
if [[ "\$AGENT_ENABLED" == "true" ]]; then
  deploy_ensure_image "\$AGENT_IMAGE"
  kubectl -n netra-system rollout restart daemonset/netra-agent
  deploy_wait_ready daemonset/netra-agent "app.kubernetes.io/name=netra-agent" "\$AGENT_IMAGE"
fi
echo "API_KEY=\$API_KEY"
echo "NETRA_URL=https://\$(hostname -I | awk '{print \$1}'):30870"
echo "NETRA ready (Hubble Relay + Cilium, HTTPS)"
curl -skf "https://127.0.0.1:30870/healthz" || curl -skf "https://\$(hostname -I | awk '{print \$1}'):30870/healthz"
EOF
)

if $DRY_RUN; then
  log "dry-run remote script:"
  echo "$remote_script"
  exit 0
fi

ssh_host 'bash -s' <<<"$remote_script"
log "done — open https://<host>:30870"
