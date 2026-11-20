#!/usr/bin/env bash
# Netra — deploy guards, sourced on the target host by scripts/deploy-remote.sh.
#
# Why this exists. deploy-remote.sh builds the images on the host and imports them
# into k3s's containerd under a FIXED tag (ghcr.io/zyvorai/netra:0.27.81), then
# runs `helm upgrade`. Kubelet garbage-collects images that no pod uses once the
# disk passes its high threshold (85% by default). A freshly imported image is
# unused until the new pod starts, so on a disk near that line the controller
# image can be collected in the gap, and the new pod fails with ImagePullBackOff
# ("NotFound": the fixed tag is not on any registry). Helm still reports success,
# `rollout status` only times out, and the controller stays down. That took the
# live controller down for about ten minutes; rolling back does not help, because
# the previous revision uses the same tag.
#
# So the deploy now (1) says so when the disk is close to the GC line, (2) makes
# sure each image is present right before helm and again after, re-importing it
# from the local build if it is missing, and (3) waits for the pods to be Ready,
# recognising ImagePullBackOff and repairing it, instead of trusting helm.
#
# Every function reads its environment, so scripts/ci-deploy-guards.sh can test
# them against stubbed df, kubectl, k3s and podman.

DEPLOY_NAMESPACE="${DEPLOY_NAMESPACE:-netra-system}"

# deploy_disk_guard [path]
#   >= NETRA_DEPLOY_WARN_DISK_PCT (default 80): warn. Kubelet starts collecting
#      unused images at 85%, and a build adds several GB.
#   >= NETRA_DEPLOY_MAX_DISK_PCT  (default 95): refuse. The builds would fail or
#      the node would start evicting pods.
#   NETRA_DEPLOY_SKIP_DISK_CHECK=1 skips it. An unreadable df is a warning, not a stop.
deploy_disk_guard() {
  local path="${1:-/}" warn="${NETRA_DEPLOY_WARN_DISK_PCT:-80}" max="${NETRA_DEPLOY_MAX_DISK_PCT:-95}" used
  if [[ "${NETRA_DEPLOY_SKIP_DISK_CHECK:-0}" == "1" ]]; then
    echo "[deploy-guard] disk check skipped (NETRA_DEPLOY_SKIP_DISK_CHECK=1)"
    return 0
  fi
  # `|| used=""`: under pipefail a failing df would otherwise abort the deploy,
  # and an unreadable disk is a warning, not a reason to stop.
  used="$(df -P "$path" 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}')" || used=""
  if [[ ! "$used" =~ ^[0-9]+$ ]]; then
    echo "[deploy-guard] warning: cannot read disk usage of ${path}; continuing" >&2
    return 0
  fi
  if (( used >= max )); then
    echo "[deploy-guard] ${path} is ${used}% full (limit ${max}%): the image builds would fail or the node would start evicting pods. Free space, or set NETRA_DEPLOY_SKIP_DISK_CHECK=1 to override." >&2
    return 1
  fi
  if (( used >= warn )); then
    echo "[deploy-guard] warning: ${path} is ${used}% full. Kubelet garbage-collects unused images above 85%, and a freshly imported image is unused until its pod starts; this deploy re-imports any image that goes missing, but free some space if you can."
  else
    echo "[deploy-guard] disk ${path}: ${used}% used"
  fi
}

deploy_image_present() { # deploy_image_present <ref>
  # Read the whole list before matching: `... | grep -q` closes the pipe at the
  # first hit, and under pipefail the resulting SIGPIPE in ctr would report a
  # present image as missing.
  local list
  list="$(sudo k3s ctr images ls -q 2>/dev/null)" || list=""
  grep -qxF "$1" <<<"$list"
}

# deploy_import_image <ref>: import a locally built image into k3s's containerd.
deploy_import_image() {
  if command -v podman >/dev/null 2>&1; then
    podman save "$1" | sudo k3s ctr images import -
  elif command -v docker >/dev/null 2>&1; then
    docker save "$1" | sudo k3s ctr images import -
  else
    echo "[deploy-guard] neither podman nor docker is available to re-import $1" >&2
    return 1
  fi
}

# deploy_ensure_image <ref>: make sure containerd has the image, re-importing the
# local build if kubelet's image GC (or anything else) removed it.
deploy_ensure_image() {
  local ref="$1"
  if deploy_image_present "$ref"; then
    return 0
  fi
  echo "[deploy-guard] ${ref} is missing from containerd (image garbage collection?); re-importing the local build"
  deploy_import_image "$ref" || return 1
  if ! deploy_image_present "$ref"; then
    echo "[deploy-guard] ${ref} is still missing after the import; the local build may be gone: rebuild it" >&2
    return 1
  fi
}

# deploy_wait_ready <workload> <label selector> <image ref> [timeout seconds]
#   workload is what `kubectl rollout status` takes: deployment/netra, daemonset/netra-agent.
#
# Waits for the ROLLOUT to complete, not merely for pods to be Ready. Right after
# `rollout restart` the previous pod is still Running and Ready and the replacement
# has not been created yet, so "every matching pod is Ready" is already true and a
# wait built on it returns at once (the first live use of this function did exactly
# that and reported success while the new pods were still starting). `rollout status`
# only succeeds once the new pods are available and the old ones are gone.
#
# It is polled in short slices so a pod stuck pulling its image can be repaired in
# between: re-import the image, then delete only the stuck pod so it is recreated
# immediately rather than after kubelet's back-off. On timeout it prints the pods
# and returns 1, so the deploy fails loudly instead of reporting a success helm
# cannot vouch for.
deploy_wait_ready() {
  local workload="$1" selector="$2" ref="$3" timeout="${4:-${NETRA_DEPLOY_READY_TIMEOUT:-600}}"
  local poll="${NETRA_DEPLOY_POLL:-5}" slice="${NETRA_DEPLOY_ROLLOUT_SLICE:-20}"
  local start="$SECONDS" lines
  while (( SECONDS - start < timeout )); do
    if kubectl -n "$DEPLOY_NAMESPACE" rollout status "$workload" --timeout="${slice}s" >/dev/null 2>&1; then
      return 0
    fi
    lines="$(kubectl -n "$DEPLOY_NAMESPACE" get pods -l "$selector" \
      -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[0].state.waiting.reason}{" "}{.status.containerStatuses[0].ready}{"\n"}{end}' 2>/dev/null || true)"
    if grep -qE 'ImagePullBackOff|ErrImagePull' <<<"$lines"; then
      echo "[deploy-guard] a pod cannot pull ${ref}: repairing"
      if deploy_ensure_image "$ref"; then
        # Only the stuck pods: kubelet would retry after a back-off of up to five
        # minutes, a fresh pod starts at once.
        grep -E 'ImagePullBackOff|ErrImagePull' <<<"$lines" | awk '{print $1}' \
          | xargs -r kubectl -n "$DEPLOY_NAMESPACE" delete pod >/dev/null 2>&1 || true
      fi
    fi
    sleep "$poll"
  done
  echo "[deploy-guard] ${workload} did not finish rolling out within ${timeout}s:" >&2
  kubectl -n "$DEPLOY_NAMESPACE" get pods -l "$selector" >&2 || true
  return 1
}
