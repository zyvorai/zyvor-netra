#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
#
# Netra — generate Packaging/Netra.icns reproducibly (macOS only; swift + iconutil, no downloads).
# Usage: macos/Packaging/make-icon.sh [output.icns]
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "make-icon.sh needs macOS" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="${1:-$here/Netra.icns}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/Netra.iconset" "$work/mod"

cat > "$work/draw.swift" <<'SW'
import AppKit
// Draws a shield with an eye glyph at the given pixel size into a PNG.
let args = CommandLine.arguments
let px = Int(args[1])!, out = args[2]
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                           hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let s = CGFloat(px)
func P(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: x * s, y: y * s) }
// Rounded-square tile (macOS icon grid: ~10% margin).
let tile = NSBezierPath(roundedRect: NSRect(x: 0.1*s, y: 0.1*s, width: 0.8*s, height: 0.8*s), xRadius: 0.18*s, yRadius: 0.18*s)
NSGradient(starting: NSColor(red: 0.05, green: 0.12, blue: 0.25, alpha: 1), ending: NSColor(red: 0.02, green: 0.30, blue: 0.45, alpha: 1))!.draw(in: tile, angle: -90)
// Shield.
let sh = NSBezierPath()
sh.move(to: P(0.5, 0.80))
sh.curve(to: P(0.72, 0.72), controlPoint1: P(0.58, 0.78), controlPoint2: P(0.66, 0.75))
sh.line(to: P(0.72, 0.52))
sh.curve(to: P(0.5, 0.22), controlPoint1: P(0.72, 0.38), controlPoint2: P(0.62, 0.28))
sh.curve(to: P(0.28, 0.52), controlPoint1: P(0.38, 0.28), controlPoint2: P(0.28, 0.38))
sh.line(to: P(0.28, 0.72))
sh.curve(to: P(0.5, 0.80), controlPoint1: P(0.34, 0.75), controlPoint2: P(0.42, 0.78))
sh.close()
NSColor(red: 0.12, green: 0.75, blue: 0.85, alpha: 1).setFill(); sh.fill()
// Eye: almond outline cut in dark, then iris and pupil.
let eye = NSBezierPath()
eye.move(to: P(0.33, 0.52))
eye.curve(to: P(0.67, 0.52), controlPoint1: P(0.43, 0.63), controlPoint2: P(0.57, 0.63))
eye.curve(to: P(0.33, 0.52), controlPoint1: P(0.57, 0.41), controlPoint2: P(0.43, 0.41))
eye.close()
NSColor(red: 0.04, green: 0.12, blue: 0.22, alpha: 1).setFill(); eye.fill()
NSColor.white.setFill()
NSBezierPath(ovalIn: NSRect(x: 0.5*s - 0.06*s, y: 0.52*s - 0.06*s, width: 0.12*s, height: 0.12*s)).fill()
NSColor(red: 0.04, green: 0.12, blue: 0.22, alpha: 1).setFill()
NSBezierPath(ovalIn: NSRect(x: 0.5*s - 0.027*s, y: 0.52*s - 0.027*s, width: 0.054*s, height: 0.054*s)).fill()
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
SW

swiftc -O -module-cache-path "$work/mod" "$work/draw.swift" -o "$work/draw"
for base in 16 32 128 256 512; do
  "$work/draw" "$base" "$work/Netra.iconset/icon_${base}x${base}.png"
  "$work/draw" "$((base*2))" "$work/Netra.iconset/icon_${base}x${base}@2x.png"
done
iconutil -c icns "$work/Netra.iconset" -o "$dest"
echo "wrote $dest"
