#!/usr/bin/env bash
# Netra — container-oriented remote deploy (one command)
# Bootstraps K3s + Cilium + Hubble when needed, builds images, Helm-installs Netra.
#
#   ./scripts/deploy-container.sh user@10.0.1.5
#   ./scripts/deploy-container.sh --skip-e2e user@10.0.1.5
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKIP_E2E=false
ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-e2e) SKIP_E2E=true; shift ;;
    -h|--help)
      sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

"${SCRIPT_DIR}/deploy-remote.sh" "${ARGS[@]}" --k3s

if ! $SKIP_E2E; then
  TARGET="${ARGS[0]:-}"
  if [[ -n "$TARGET" ]]; then
    ssh -o StrictHostKeyChecking=accept-new "$TARGET" \
      'kubectl -n kube-system get ds cilium && kubectl -n kube-system get deploy hubble-relay && kubectl -n netra-system get deploy netra'
  fi
fi
