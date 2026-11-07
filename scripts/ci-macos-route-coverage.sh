#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#
# Netra — macOS client route-coverage gate (no build, no root)
#
# Every `/api/v1/...` route the controller registers in internal/api must either be
# referenced somewhere under macos/Sources or carry a reasoned waiver in
# macos/route-waivers.txt (`VERB /path # reason`). Segments written `{name}` match any
# one path segment in the Swift source (including `\(interpolation)`); a route ending in
# `/` matches as a prefix. Matching is by path only, so a verb that the app never calls
# on an otherwise referenced path is not detected: review waivers and new routes by hand.
#
# Usage:
#   ./scripts/ci-macos-route-coverage.sh
# Exits 1 when any route is neither referenced nor waived.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
src=macos/Sources
waivers=macos/route-waivers.txt

[ -d "$src" ] || { echo "missing $src" >&2; exit 2; }
[ -f "$waivers" ] || { echo "missing $waivers" >&2; exit 2; }

# Every registered route, "VERB /path", from any non-test Go file under internal/ and cmd/.
routes="$(grep -rhoE 'Handle(Func)?\("[A-Z]+ /api/v1/[^"]*"' internal cmd --include='*.go' --exclude='*_test.go' \
  | sed -E 's/^Handle(Func)?\("//; s/"$//' | sort -u)"
[ -n "$routes" ] || { echo "no routes found; extraction is broken" >&2; exit 2; }

# Waivers: strip comments and blanks, keep "VERB /path".
waived="$(sed -E 's/[[:space:]]*#.*$//; /^[[:space:]]*$/d; s/[[:space:]]+/ /g' "$waivers" | sort -u)"

total=0 covered=0 waivedn=0
uncovered=""
while IFS= read -r route; do
  [ -n "$route" ] || continue
  total=$((total + 1))
  path="${route#* }"
  rel="${path#/}"
  # Escape regex metacharacters, then wildcard {segments}.
  pat="$(printf '%s' "$rel" | sed -E 's/[][\.^$*+?()|]/\\&/g; s/\{[^}]*\}/[^\/" ]+/g')"
  # Left edge: start of a string or after a slash; right edge: not a longer segment name
  # (so /ebpf/allow is not satisfied by /ebpf/allow-cidr). Prefix routes (trailing /) skip the right edge.
  case "$rel" in */) edge="" ;; *) edge='([^A-Za-z0-9_-]|$)' ;; esac
  if grep -rqE -- "(^|[^A-Za-z0-9_-])${pat}${edge}" "$src" 2>/dev/null; then
    covered=$((covered + 1))
  elif printf '%s\n' "$waived" | grep -qxF -- "$route"; then
    waivedn=$((waivedn + 1))
  else
    uncovered="${uncovered}${route}"$'\n'
  fi
done <<< "$routes"

# Waivers that name no registered route are stale.
stale="$(comm -13 <(printf '%s\n' "$routes") <(printf '%s\n' "$waived" | sed '/^$/d'))"
if [ -n "$stale" ]; then
  echo "warning: waivers naming no registered route:" >&2
  printf '  %s\n' $'\n'"$stale" | sed '/^  $/d' >&2
fi

echo "routes: $total, referenced: $covered, waived: $waivedn, uncovered: $(printf '%s' "$uncovered" | grep -c . || true)"
if [ -n "$uncovered" ]; then
  echo "UNCOVERED (reference in macos/Sources or add a reasoned waiver to $waivers):"
  printf '%s' "$uncovered" | sed 's/^/  /'
  exit 1
fi
echo "ok"
