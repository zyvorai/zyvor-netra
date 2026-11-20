#!/usr/bin/env bash
# Netra — deploy guards gate (no cluster, no root)
#
# scripts/lib/deploy-guards.sh is sourced on the target host by deploy-remote.sh
# (docs in that file). This exercises it against stubbed df, sudo, k3s, podman and
# kubectl, including the failure that took the live controller down for about ten
# minutes: the freshly imported image is garbage-collected before its pod starts,
# the pod sticks in ImagePullBackOff, and helm still reports success.
#
# Usage:
#   ./scripts/ci-deploy-guards.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STUB="$(mktemp -d "${TMPDIR:-/tmp}/netra-guards.XXXXXX")"
trap 'rm -rf "$STUB"' EXIT
export STUB
IMG="ghcr.io/zyvorai/netra:0.27.81"

pass=0
fail=0
check() { # check <name> <command...>   (passes when the command succeeds)
  local name="$1"
  shift
  if "$@"; then pass=$((pass + 1)); echo "PASS  $name"; else fail=$((fail + 1)); echo "FAIL  $name" >&2; fi
}

# --- stubs -----------------------------------------------------------------
mkdir -p "$STUB/bin"
cat >"$STUB/bin/df" <<'EOF'
#!/usr/bin/env bash
if [[ -f "$STUB/df.out" ]]; then cat "$STUB/df.out"; else exit 1; fi
EOF
cat >"$STUB/bin/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF
cat >"$STUB/bin/k3s" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "ctr images ls -q") cat "$STUB/images" 2>/dev/null || true ;;
  "ctr images import -") cat >/dev/null; echo "$IMG" >>"$STUB/images"; echo "import" >>"$STUB/log" ;;
esac
EOF
cat >"$STUB/bin/podman" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == save ]] && echo "fake-image-archive"
EOF
cat >"$STUB/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$STUB/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *"rollout status"*)
    n=$(cat "$STUB/rcalls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB/rcalls"
    f="$STUB/rollout.$n"; [[ -f "$f" ]] || f="$STUB/rollout.last"
    exit "$(cat "$f" 2>/dev/null || echo 1)" ;;
  *"get pods"*)
    n=$(cat "$STUB/calls" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$STUB/calls"
    f="$STUB/pods.$n"; [[ -f "$f" ]] || f="$STUB/pods.last"; cat "$f" ;;
  *"delete pod"*) echo "delete $*" >>"$STUB/log" ;;
esac
EOF
chmod +x "$STUB"/bin/*
export IMG PATH="$STUB/bin:$PATH"
export NETRA_DEPLOY_POLL=0

# shellcheck source=lib/deploy-guards.sh
source "$ROOT/scripts/lib/deploy-guards.sh"

reset() { rm -f "$STUB"/{df.out,images,log,calls,rcalls} "$STUB"/pods.* "$STUB"/rollout.*; : >"$STUB/log"; }
# rollout <n> <rc>: what the n-th `rollout status` returns (rollout last <rc> for every later call).
rollout() { echo "$2" >"$STUB/rollout.$1"; }
imports() { grep -c '^import$' "$STUB/log" || true; }
deletes() { grep -c '^delete' "$STUB/log" || true; }
df_out() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda2 1000 %s %s %s%% /\n' "$1" "$((1000 - $1))" "$1" >"$STUB/df.out"; }

# --- disk guard --------------------------------------------------------------
reset; df_out 70
out="$(deploy_disk_guard / 2>&1)"; check "disk 70%: ok, no warning" bash -c '! grep -q warning <<<"$0"' "$out"
reset; df_out 84
out="$(deploy_disk_guard / 2>&1)"; rc=$?
check "disk 84% (the live host): warns but proceeds" bash -c 'grep -q "warning" <<<"$0" && grep -q "85%" <<<"$0"' "$out"
check "disk 84%: exit status is success" test "$rc" -eq 0
reset; df_out 96
if deploy_disk_guard / >/dev/null 2>&1; then rc=0; else rc=1; fi
check "disk 96%: refuses" test "$rc" -eq 1
reset; df_out 96
if NETRA_DEPLOY_SKIP_DISK_CHECK=1 deploy_disk_guard / >/dev/null 2>&1; then rc=0; else rc=1; fi
check "disk 96% with the override: proceeds" test "$rc" -eq 0
# No df output at all (df failing) must not abort a script running under set -e -o pipefail.
reset
if out="$(deploy_disk_guard / 2>&1)"; then rc=0; else rc=1; fi
check "unreadable df is a warning, not a stop" test "$rc" -eq 0
check "unreadable df says so" bash -c 'grep -q "cannot read disk usage" <<<"$0"' "$out"
reset; df_out 82
out="$(NETRA_DEPLOY_WARN_DISK_PCT=90 deploy_disk_guard / 2>&1)"; check "the warning threshold is configurable" bash -c '! grep -q warning <<<"$0"' "$out"

# --- image presence ------------------------------------------------------------
reset; echo "$IMG" >"$STUB/images"
deploy_ensure_image "$IMG" >/dev/null; check "image present: nothing is imported" test "$(imports)" -eq 0
reset
deploy_ensure_image "$IMG" >/dev/null; check "image missing (GC'd): it is re-imported once" test "$(imports)" -eq 1
check "image is present after the re-import" deploy_image_present "$IMG"
# A long list with the match first: `ctr | grep -q` would SIGPIPE under pipefail and call it missing.
reset; { echo "$IMG"; for i in $(seq 1 20000); do echo "docker.io/library/filler-$i:latest"; done; } >"$STUB/images"
check "a present image in a long list is found (no SIGPIPE false negative)" deploy_image_present "$IMG"
reset; echo "ghcr.io/zyvorai/netra:0.27.8" >"$STUB/images"
if deploy_image_present "$IMG"; then rc=0; else rc=1; fi
check "a different tag is not mistaken for the image (exact match)" test "$rc" -eq 1

# --- waiting for the rollout, and the outage itself ------------------------------
SEL="app.kubernetes.io/name=netra"
WL="deployment/netra"

reset; rollout last 0
echo "netra-abc  true" >"$STUB/pods.last"
if deploy_wait_ready "$WL" "$SEL" "$IMG" 5 >/dev/null 2>&1; then rc=0; else rc=1; fi
check "a completed rollout returns at once" test "$rc" -eq 0

# THE FLAW the first live use exposed: right after `rollout restart` the OLD pod is still
# Running and Ready and the replacement does not exist yet, so a wait that only asks "are
# all matching pods Ready?" succeeds immediately. The rollout is not done, and it must say so.
reset
echo "netra-old  true" >"$STUB/pods.last" # a Ready pod is all that is listed
rollout 1 1; rollout 2 1; rollout 3 1; rollout last 0
if deploy_wait_ready "$WL" "$SEL" "$IMG" 5 >/dev/null 2>&1; then rc=0; else rc=1; fi
check "an old Ready pod does not end the wait while the rollout is incomplete" test "$rc" -eq 0
check "it kept polling the rollout until it finished (4 calls)" test "$(cat "$STUB/rcalls")" -eq 4

reset
echo "netra-old  true" >"$STUB/pods.last"
rollout last 1 # the rollout never completes, whatever the pods look like
if deploy_wait_ready "$WL" "$SEL" "$IMG" 1 >/dev/null 2>&1; then rc=0; else rc=1; fi
check "a Ready old pod is not success when the rollout never completes" test "$rc" -eq 1

# The outage: the new pod is stuck in ImagePullBackOff, the image is gone from
# containerd. It must be re-imported and the stuck pod deleted so it restarts at once;
# the wait then succeeds once the rollout completes.
reset
echo "netra-new ImagePullBackOff false" >"$STUB/pods.last"
rollout 1 1; rollout 2 1; rollout last 0
if out="$(deploy_wait_ready "$WL" "$SEL" "$IMG" 5 2>&1)"; then rc=0; else rc=1; fi
check "ImagePullBackOff with the image GC'd: repaired and the wait succeeds" test "$rc" -eq 0
check "the repair re-imported the image" test "$(imports)" -ge 1
check "the repair deleted the stuck pod so it restarts at once" grep -q "delete .*netra-new" "$STUB/log"

# Never rolls out: fails loudly and prints the pods.
reset; echo "netra-x CrashLoopBackOff false" >"$STUB/pods.last"; rollout last 1
if out="$(deploy_wait_ready "$WL" "$SEL" "$IMG" 1 2>&1)"; then rc=0; else rc=1; fi
check "never rolls out: returns failure" test "$rc" -eq 1
check "never rolls out: says so and shows the pods" bash -c 'grep -q "did not finish rolling out" <<<"$0"' "$out"
# A non-pull failure must not be "repaired" by re-importing the image.
check "a crash loop does not trigger an image re-import" test "$(imports)" -eq 0
check "a crash loop does not delete pods" test "$(deletes)" -eq 0

# --- the generated remote script ------------------------------------------------
# deploy-remote.sh assembles the script it runs on the host through several layers
# of escaping. Render it (--dry-run, with ssh stubbed to answer the one question it
# asks before rendering) and check it parses and wires the guards in the right order.
cat >"$STUB/bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf '%s' /home/testuser
EOF
chmod +x "$STUB/bin/ssh"
rendered="$STUB/remote.sh"
NETRA_AGENT_ENABLED=true "$ROOT/scripts/deploy-remote.sh" testuser@testhost --dry-run 2>/dev/null | sed '1d' >"$rendered"
check "the remote script renders" test -s "$rendered"
check "the remote script parses" bash -n "$rendered"
line() { grep -n -m1 -- "$1" "$rendered" | cut -d: -f1; }
check "it sources the guards and checks the disk before building" \
  test "$(line 'source scripts/lib/deploy-guards.sh')" -lt "$(line '^  build_image$')"
check "both images are built before either is imported (the GC window)" \
  test "$(line '^ *build_agent_image$')" -lt "$(line '^  import_image$')"
check "the images are ensured before helm upgrade" \
  test "$(line 'deploy_ensure_image "$CONTROLLER_IMAGE"')" -lt "$(line 'helm upgrade --install')"
check "the controller is waited for until its rollout completes" \
  grep -q 'deploy_wait_ready deployment/netra "app.kubernetes.io/name=netra" "$CONTROLLER_IMAGE"' "$rendered"
check "the agent is waited for until its rollout completes too" \
  grep -q 'deploy_wait_ready daemonset/netra-agent "app.kubernetes.io/name=netra-agent" "$AGENT_IMAGE"' "$rendered"
check "the fragile 180 s rollout status command is gone" bash -c '! grep -q "kubectl .*rollout status" "$0"' "$rendered"

echo
echo "deploy guards: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]] || exit 1
echo "==> PASS ci-deploy-guards"
