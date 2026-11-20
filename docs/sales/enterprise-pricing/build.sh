#!/usr/bin/env bash
# Rebuild the Netra Enterprise pricing sheets (five JPEGs) and the combined PDF from sheets.html.
# Needs Google Chrome, node with web/node_modules installed, macOS `sips`, and python3 with PyMuPDF.
#   ./docs/sales/enterprise-pricing/build.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/netra-pricing.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

node "$HERE/build.cjs" "$OUT"
for png in "$OUT"/*.png; do
  sips -s format jpeg -s formatOptions 90 "$png" --out "$HERE/$(basename "${png%.png}").jpg" >/dev/null
done

PDF="$HERE/../Zyvor-Netra-Enterprise-Pricing.pdf"
python3 - "$OUT" "$PDF" <<'PYEOF'
import glob, sys, fitz
out, dest = sys.argv[1], sys.argv[2]
merged = fitz.open()
for f in sorted(glob.glob(out + "/*.pdf")):
    d = fitz.open(f)
    assert d.page_count == 1, (f, d.page_count)
    merged.insert_pdf(d)
merged.set_metadata({"title": "Netra Enterprise packaging and pricing", "author": "Zyvor AI Labs Private Limited", "subject": "September 2026"})
merged.save(dest, deflate=True, garbage=3)
print("wrote", dest, merged.page_count, "pages")
PYEOF
cp "$PDF" "$ROOT/website/static/sales/Zyvor-Netra-Enterprise-Pricing.pdf"
echo "sheets: $(command ls "$HERE"/0*.jpg | wc -l) JPEGs written; website copy updated"
