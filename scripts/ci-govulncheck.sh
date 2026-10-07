#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
# Netra — govulncheck gate (no root, no cluster)
#
# Fails when the code can reach (symbol level) a known-vulnerable dependency,
# except for advisories listed in scripts/govulncheck-ignore.txt with a reason.
# The scanner version is pinned so a new release cannot turn CI red by itself.
# An ignore entry that no longer matches anything is reported so it can be
# removed, but does not fail the job.
#
# Usage:
#   ./scripts/ci-govulncheck.sh
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=v1.7.0
IGNORE_FILE=scripts/govulncheck-ignore.txt

command -v jq >/dev/null || { echo "ci-govulncheck: jq is required" >&2; exit 2; }

out=$(mktemp)
trap 'rm -f "$out"' EXIT

go run "golang.org/x/vuln/cmd/govulncheck@${VERSION}" -format json ./... >"$out"

reachable=$(jq -r 'select(.finding and (.finding.trace[0].function // "") != "") | .finding.osv' "$out" | sort -u)
ignored=$(sed -e 's/#.*//' "$IGNORE_FILE" | awk 'NF {print $1}' | sort -u)

fail=0
for id in $reachable; do
  if grep -qx "$id" <<<"$ignored"; then
    echo "ignored   $id ($(grep -m1 "^$id" "$IGNORE_FILE" | cut -d' ' -f2- | sed 's/^ *//'))"
  else
    summary=$(jq -r --arg id "$id" 'select(.osv.id == $id) | .osv.summary' "$out" | head -1)
    echo "REACHABLE $id: $summary (https://pkg.go.dev/vuln/$id)" >&2
    jq -r --arg id "$id" 'select(.finding.osv == $id and (.finding.trace[0].function // "") != "")
      | .finding.trace | last | "            \(.package).\(.function) at \(.position.filename // "?"):\(.position.line // 0)"' "$out" | sort -u | head -5 >&2
    fail=1
  fi
done

for id in $ignored; do
  grep -qx "$id" <<<"$reachable" || echo "stale     $id is in $IGNORE_FILE but no longer reported; remove it"
done

if [[ $fail -ne 0 ]]; then
  echo "ci-govulncheck: FAILED (upgrade the dependency, or add a justified entry to $IGNORE_FILE)" >&2
  exit 1
fi
echo "ci-govulncheck: ok ($(wc -w <<<"$reachable" | tr -d ' ') reachable, all justified)"
