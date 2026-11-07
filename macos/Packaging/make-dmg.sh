#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#
# Netra — package Netra.app into a signed (optional) and notarized (optional) .dmg
#
# Usage: macos/Packaging/make-dmg.sh   (run build-app.sh first)
# Env:
#   OUT_DIR            directory holding Netra.app and receiving Netra.dmg (default: macos/dist)
#   CODESIGN_IDENTITY  sign the dmg when set and not "-" (a Developer ID Application identity)
#   Notarization runs only when one of these is configured (and CODESIGN_IDENTITY is a real identity):
#     NOTARY_KEYCHAIN_PROFILE                         notarytool keychain profile name, or
#     NOTARY_APPLE_ID + NOTARY_TEAM_ID + NOTARY_PASSWORD   Apple ID with an app-specific password, or
#     NOTARY_API_KEY_PATH + NOTARY_API_KEY_ID [+ NOTARY_API_ISSUER]   App Store Connect API key (.p8 file)
# Idempotent: the dmg is rebuilt on every run.
set -euo pipefail

[ "$(uname -s)" = Darwin ] || { echo "make-dmg.sh needs macOS" >&2; exit 2; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${OUT_DIR:-$(cd "$here/.." && pwd)/dist}"
identity="${CODESIGN_IDENTITY:--}"
app="$out/Netra.app"
dmg="$out/Netra.dmg"

[ -d "$app" ] || { echo "missing $app: run macos/Packaging/build-app.sh first" >&2; exit 1; }

stage="$(mktemp -d "${TMPDIR:-/tmp}/netra-dmg.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
cp -R "$app" "$stage/Netra.app"
ln -s /Applications "$stage/Applications"

rm -f "$dmg"
echo "==> hdiutil create $dmg"
hdiutil create -volname Netra -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg" >/dev/null

signed=0
if [ "$identity" != - ]; then
  echo "==> codesign dmg"
  codesign --force --timestamp --sign "$identity" ${CODESIGN_KEYCHAIN:+--keychain "$CODESIGN_KEYCHAIN"} "$dmg"
  codesign --verify --verbose=2 "$dmg"
  signed=1
else
  echo "dmg not signed (CODESIGN_IDENTITY unset or ad-hoc)"
fi

notary=()
if [ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]; then
  notary=(--keychain-profile "$NOTARY_KEYCHAIN_PROFILE")
elif [ -n "${NOTARY_APPLE_ID:-}" ] && [ -n "${NOTARY_TEAM_ID:-}" ] && [ -n "${NOTARY_PASSWORD:-}" ]; then
  notary=(--apple-id "$NOTARY_APPLE_ID" --team-id "$NOTARY_TEAM_ID" --password "$NOTARY_PASSWORD")
elif [ -n "${NOTARY_API_KEY_PATH:-}" ] && [ -n "${NOTARY_API_KEY_ID:-}" ]; then
  notary=(--key "$NOTARY_API_KEY_PATH" --key-id "$NOTARY_API_KEY_ID")
  [ -n "${NOTARY_API_ISSUER:-}" ] && notary+=(--issuer "$NOTARY_API_ISSUER")
fi

if [ "${#notary[@]}" -eq 0 ]; then
  echo "notarization skipped: no NOTARY_* credentials provided"
elif [ "$signed" -ne 1 ]; then
  echo "notarization skipped: the dmg is not signed with a Developer ID identity" >&2
else
  echo "==> notarytool submit --wait"
  xcrun notarytool submit "$dmg" "${notary[@]}" --wait
  xcrun stapler staple "$dmg"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
fi

echo "built $dmg"
