#!/usr/bin/env bash
# Netra — agent image gate (needs a container engine; no root, no BPF attach)
#
# Builds Dockerfile.agent, which compiles every BPF object with the image's own
# clang, and then checks what actually shipped:
#
#   * the agent binary is present and executable;
#   * every bpf/netra_*.c has a matching /opt/netra/bpf/<name>.o in the image,
#     and each is a real BPF ELF object.
#
# The second check is the point: a sensor added under bpf/ but not to the
# Dockerfile would build, pass every unit test, and ship an agent that quietly
# never loads it. The runtime treats a missing object as "feature unavailable",
# so nothing else would notice.
#
# Usage:
#   ./scripts/ci-agent-image.sh
#   CONTAINER_CLI=podman ./scripts/ci-agent-image.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLI="${CONTAINER_CLI:-docker}"
TAG="${IMAGE_TAG:-netra-agent:ci-image-gate}"

command -v "$CLI" >/dev/null 2>&1 || { echo "missing container engine: $CLI" >&2; exit 1; }

echo "==> build Dockerfile.agent (${CLI})"
"$CLI" build -f Dockerfile.agent -t "$TAG" .

work="$(mktemp -d)"
cid=""
cleanup() {
  [[ -n "$cid" ]] && "$CLI" rm -f "$cid" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# The final image is distroless (no shell), so read it through a stopped
# container's filesystem instead of running anything in it.
cid="$("$CLI" create "$TAG")"
"$CLI" export "$cid" | tar -x -C "$work" ./netra-agent ./opt/netra/bpf 2>/dev/null \
  || "$CLI" export "$cid" | tar -x -C "$work" netra-agent opt/netra/bpf

echo "==> agent binary"
[[ -x "$work/netra-agent" ]] || { echo "/netra-agent missing or not executable in the image" >&2; exit 1; }

echo "==> BPF objects shipped in the image"
fail=0
for src in bpf/netra_*.c; do
  name="$(basename "$src" .c)"
  obj="$work/opt/netra/bpf/${name}.o"
  if [[ ! -s "$obj" ]]; then
    echo "  MISSING  ${name}.o (built from ${src}, not copied into the image: add it to Dockerfile.agent)" >&2
    fail=1
    continue
  fi
  # ELF magic, and e_machine 0xF7 (EM_BPF) at offset 18.
  magic="$(head -c 4 "$obj" | od -An -c | tr -d ' \n')"
  machine="$(dd if="$obj" bs=1 skip=18 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  if [[ "$magic" != '177ELF' || "$machine" != 'f7' ]]; then
    echo "  BAD      ${name}.o is not a BPF ELF object (magic=${magic} machine=${machine})" >&2
    fail=1
    continue
  fi
  echo "  ok       ${name}.o"
done
# And nothing shipped that has no source: a stale COPY line for a removed sensor.
for obj in "$work"/opt/netra/bpf/*.o; do
  name="$(basename "$obj" .o)"
  [[ -e "bpf/${name}.c" ]] || { echo "  STRAY    ${name}.o has no bpf/${name}.c" >&2; fail=1; }
done
(( fail == 0 )) || exit 1

echo "==> PASS ci-agent-image"
