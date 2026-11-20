#!/usr/bin/env python3
"""Build the Netra product brochure PDF.

    python3 docs/sales/brochure/build.py            # writes Zyvor-Netra-Product-Brochure.pdf here
    python3 docs/sales/brochure/build.py --check    # also fail if any page's content overflows

Pure standard library. The PDF is rendered by the system Google Chrome in headless mode (set CHROME to
another Chromium-based browser). Diagrams are drawn by diagrams.py; screenshots come from docs/ux/.
"""
import glob, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import diagrams  # noqa: E402

CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
OUT = os.path.join(HERE, "Zyvor-Netra-Product-Brochure.pdf")
BUILT = os.path.join(HERE, "_built.html")
MARK = "../../../web/public/zyvor-mark.svg"

CHECK_JS = """<script>
window.addEventListener('load', function () {
  document.querySelectorAll('.page').forEach(function (p) {
    var b = p.querySelector('.body');
    var last = b.lastElementChild;
    var bottom = last ? last.getBoundingClientRect().bottom - b.getBoundingClientRect().top : 0;
    p.setAttribute('data-overflow', bottom > b.clientHeight + 1 ? '1' : '0');
    p.setAttribute('data-fill', String(Math.round(100 * bottom / b.clientHeight)));
  });
  document.documentElement.setAttribute('data-checked', '1');
});
</script>"""


def assemble():
    pages = ""
    for f in sorted(glob.glob(os.path.join(HERE, "pages_*.html"))):
        pages += open(f, encoding="utf-8").read() + "\n"
    pages = re.sub(r"\{\{dia:(\w+)\}\}", lambda m: diagrams.ALL[m.group(1)](), pages)
    n = [0]

    def wrap(m):
        n[0] += 1
        head = m.group(1)
        return (f'{head}<div class="hdr"><img src="{MARK}" alt=""><b>ZYVOR</b><span>&middot;</span><span>NETRA PRODUCT BROCHURE</span></div>')

    pages = re.sub(r'(<section class="page[^"]*"[^>]*>)', wrap, pages)
    total = n[0]
    idx = [0]

    def foot(m):
        idx[0] += 1
        return f'<div class="ftr"><span>zyvor.dev</span><span>Netra product brochure</span><span>Page {idx[0]} of {total}</span></div></section>'

    pages = re.sub(r"</section>", foot, pages)
    css = open(os.path.join(HERE, "style.css"), encoding="utf-8").read()
    html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Zyvor Netra Product Brochure</title>'
            f"<style>{css}</style></head><body>{pages}{CHECK_JS}</body></html>")
    open(BUILT, "w", encoding="utf-8").write(html)
    return total


def chrome(args):
    return subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-sandbox"] + args, capture_output=True, text=True, timeout=180)


def main():
    if not os.path.exists(CHROME):
        sys.exit(f"Chrome not found at {CHROME}; set CHROME to a Chromium-based browser")
    total = assemble()
    url = "file://" + BUILT
    if "--check" in sys.argv:
        r = chrome(["--virtual-time-budget=4000", "--dump-dom", url])
        bad = [(int(i) + 1, fill) for i, (o, fill) in enumerate(re.findall(r'data-overflow="(\d)" data-fill="(\d+)"', r.stdout)) if o == "1"]
        fills = re.findall(r'data-fill="(\d+)"', r.stdout)
        print("content fill per page (% of usable height): " + ", ".join(f"{i + 1}:{f}" for i, f in enumerate(fills)))
        if len(fills) != total:
            sys.exit(f"expected {total} pages in the check, found {len(fills)}")
        if bad:
            sys.exit("content overflows on page(s): " + ", ".join(f"{p} ({f}%)" for p, f in bad))
    r = chrome(["--no-pdf-header-footer", "--virtual-time-budget=4000", f"--print-to-pdf={OUT}", url])
    if not os.path.exists(OUT):
        sys.exit("Chrome did not write the PDF:\n" + r.stderr[-800:])
    print(f"wrote {OUT} ({os.path.getsize(OUT) // 1024} KB, {total} pages)")


if __name__ == "__main__":
    main()
