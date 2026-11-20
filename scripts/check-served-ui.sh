#!/usr/bin/env bash
# Netra — the UI a running controller serves is complete (no root, no toolchain)
#
# The controller answers unknown paths with the app's index.html (single-page fallback), so a static
# file that never made it into the image does not 404: it "loads" as an HTML page and the browser
# shows a broken image. That is how a release shipped without its logo while every health probe
# passed. This fetches, from a RUNNING controller:
#   - the root page, and every /absolute asset it references (scripts, styles, icons)
#   - every file in web/public/, which Vite copies to the site root (logo, favicon)
# and fails unless each one answers 200, is not the HTML fallback, and (for web/public) is
# byte-for-byte the file in the repository.
#
# Usage:
#   ./scripts/check-served-ui.sh http://127.0.0.1:30870
#   ./scripts/check-served-ui.sh https://127.0.0.1:30870 -k      # extra args go to curl
set -euo pipefail

BASE="${1:?usage: check-served-ui.sh <base-url> [curl args]}"; shift || true
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d "${TMPDIR:-/tmp}/netra-ui.XXXXXX")"; trap 'rm -rf "$W"' EXIT
fail=0
bad() { echo "FAIL  $*" >&2; fail=1; }

get() { # get <path> <out>: prints "<status> <content-type>"
  curl -s --max-time 20 "${CURL_ARGS[@]}" -o "$2" -w '%{http_code} %{content_type}' "$BASE$1"
}
CURL_ARGS=("$@")

read -r code ctype < <(get / "$W/index.html") || true
[[ "$code" == 200 ]] || { echo "FAIL  GET / -> $code" >&2; exit 1; }
grep -qi '<html' "$W/index.html" || { echo "FAIL  GET / is not an HTML page" >&2; exit 1; }
echo "ok    / ($ctype)"

# Assets the served page itself references.
refs=$(grep -oE '(href|src)="/[^"]+"' "$W/index.html" | sed -E 's/^(href|src)="([^"]+)"$/\2/' | sort -u)
[[ -n "$refs" ]] || bad "the served page references no assets"
n=0
for path in $refs; do
  read -r code ctype < <(get "$path" "$W/asset") || true
  if [[ "$code" != 200 ]]; then bad "$path -> HTTP $code"; continue; fi
  case "$ctype" in text/html*) bad "$path -> served the HTML fallback, the file is not in the image";; *) n=$((n+1));; esac
done
echo "ok    $n asset(s) referenced by the page"

# Every file in web/public must be served at the site root, unchanged.
m=0
for f in "$ROOT"/web/public/*; do
  [[ -f "$f" ]] || continue
  name="/$(basename "$f")"
  read -r code ctype < <(get "$name" "$W/pub") || true
  if [[ "$code" != 200 ]]; then bad "$name -> HTTP $code"; continue; fi
  case "$ctype" in text/html*) bad "$name -> served the HTML fallback: web/public is missing from the build"; continue;; esac
  cmp -s "$f" "$W/pub" || { bad "$name differs from web/public/$(basename "$f")"; continue; }
  m=$((m+1)); echo "ok    $name ($ctype, identical to the repository file)"
done
[[ "$m" -ge 1 ]] || bad "web/public has no files to compare"
[[ "$fail" == 0 ]] && echo "PASS served UI is complete" || { echo "served UI is incomplete" >&2; exit 1; }
