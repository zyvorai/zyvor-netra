#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#
# Netra — build and sign Netra.app (macOS only)
#
# Usage: macos/Packaging/build-app.sh
# Env:
#   OUT_DIR            output directory (default: macos/dist); Netra.app is created inside it
#   BUILD_PATH         swift --build-path (default: .build under macos/)
#   NETRA_VERSION      short version (default: `git describe` with a leading v / macos-v removed)
#   NETRA_BUILD        build number (default: commit count, else 1)
#   UNIVERSAL          1 (default) tries arm64+x86_64; 0 builds the host arch only
#   CODESIGN_IDENTITY  signing identity (default "-", ad-hoc). Never stored in the repo.
#   CODESIGN_KEYCHAIN  optional keychain path holding the identity
# Idempotent: Netra.app is rebuilt from scratch on every run.
set -euo pipefail

[ "$(uname -s)" = Darwin ] || { echo "build-app.sh needs macOS" >&2; exit 2; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
macos="$(cd "$here/.." && pwd)"
out="${OUT_DIR:-$macos/dist}"
identity="${CODESIGN_IDENTITY:--}"
app="$out/Netra.app"

version="${NETRA_VERSION:-$(git -C "$macos" describe --tags --always 2>/dev/null || echo 0.0.0)}"
version="${version#macos-}"
version="${version#v}"
# CFBundleShortVersionString allows only digits and dots: keep the leading numeric part.
short="$(printf '%s' "$version" | sed -E 's/^([0-9]+(\.[0-9]+){0,2}).*/\1/')"
case "$short" in [0-9]*) ;; *) short=0.0.0 ;; esac
build="${NETRA_BUILD:-$(git -C "$macos" rev-list --count HEAD 2>/dev/null || echo 1)}"

swift_args=(build -c release --package-path "$macos" --product Netra)
[ -n "${BUILD_PATH:-}" ] && swift_args+=(--build-path "$BUILD_PATH")

arch_args=(--arch arm64 --arch x86_64)
if [ "${UNIVERSAL:-1}" = 1 ]; then
  echo "==> swift build (universal arm64+x86_64)"
  if ! swift "${swift_args[@]}" ${arch_args[@]+"${arch_args[@]}"}; then
    echo "NOTE: universal build failed; falling back to the host architecture ($(uname -m)) only." >&2
    arch_args=()
    swift "${swift_args[@]}"
  fi
else
  echo "==> swift build (host arch $(uname -m) only, UNIVERSAL=0)"
  arch_args=()
  swift "${swift_args[@]}"
fi
bin_dir="$(swift "${swift_args[@]}" ${arch_args[@]+"${arch_args[@]}"} --show-bin-path)"
bin="$bin_dir/Netra"
[ -x "$bin" ] || { echo "missing built executable $bin" >&2; exit 1; }
echo "    archs: $(lipo -archs "$bin")"

echo "==> assemble $app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/Netra"
cp "$here/Info.plist" "$app/Contents/Info.plist"
plist="$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable Netra" "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $short" "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $build" "$plist"
if [ -f "$here/Netra.icns" ]; then
  cp "$here/Netra.icns" "$app/Contents/Resources/Netra.icns"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string Netra" "$plist"
else
  echo "    no Packaging/Netra.icns; building without an app icon"
fi
# SwiftPM resource bundles (none today) sit next to the binary.
for b in "$bin_dir"/*.bundle; do
  [ -e "$b" ] && cp -R "$b" "$app/Contents/Resources/"
done
plutil -lint "$plist"

echo "==> codesign (identity: $([ "$identity" = - ] && echo ad-hoc || echo "$identity"))"
sign_args=(--force --options runtime --entitlements "$here/Netra.entitlements" --sign "$identity")
[ "$identity" != - ] && sign_args+=(--timestamp)
[ -n "${CODESIGN_KEYCHAIN:-}" ] && sign_args+=(--keychain "$CODESIGN_KEYCHAIN")
codesign "${sign_args[@]}" "$app"
codesign --verify --deep --strict --verbose=2 "$app"

echo "built $app (version $short, build $build)"
