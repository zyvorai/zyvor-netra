#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
# Render the README cards (docs/social/readme/*.html) to JPEGs in docs/ux/.
# Needs Google Chrome and macOS `sips` (both already on a Mac); nothing is installed.
#   ./docs/social/readme/build.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../../ux"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[[ -x "$CHROME" ]] || { echo "Google Chrome not found (set CHROME=...)" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/netra-readme.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
render() { # <html> <jpg> <height>
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --window-size="1600,$3" --screenshot="$TMP/$2.png" "file://$HERE/$1" >/dev/null 2>&1
  sips -s format jpeg -s formatOptions 90 "$TMP/$2.png" --out "$OUT/$2" >/dev/null
  echo "wrote docs/ux/$2 ($(du -k "$OUT/$2" | cut -f1) KB)"
}
render how-it-works.html readme-how-it-works.jpg 560
render capabilities.html readme-capabilities.jpg 700
render lease-safety.html readme-lease-safety.jpg 560
