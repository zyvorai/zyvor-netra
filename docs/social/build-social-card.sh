#!/usr/bin/env bash
# Render docs/social/netra-social-card.html (1600x900) to a JPEG for LinkedIn and X.
# Needs Google Chrome and macOS `sips` (both already on a Mac); nothing is installed.
#   ./docs/social/build-social-card.sh [output.jpg]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/netra-social-card.jpg}"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[[ -x "$CHROME" ]] || { echo "Google Chrome not found (set CHROME=...)" >&2; exit 1; }
PNG="$(mktemp "${TMPDIR:-/tmp}/netra-card.XXXXXX.png")"
trap 'rm -f "$PNG"' EXIT
"$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1600,900 --screenshot="$PNG" "file://$HERE/netra-social-card.html" >/dev/null 2>&1
sips -s format jpeg -s formatOptions 92 "$PNG" --out "$OUT" >/dev/null
echo "wrote $OUT ($(sips -g pixelWidth -g pixelHeight "$OUT" | awk '/pixel/{printf "%s ", $2}')px, $(du -k "$OUT" | cut -f1) KB)"
