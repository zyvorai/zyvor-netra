"""Tiny SVG helpers for the brochure diagrams (stdlib only)."""
import html, textwrap

INK, SOFT, LINE, WARM = "#0d0d0c", "#5a544c", "#d9cfc2", "#fbf7f2"
SIG, DEEP = "#ff5a15", "#cc420a"
RED, GREEN, BLUE = "#b3261e", "#1f7a4d", "#2b5fd9"
GREY, PALE = "#efe9df", "#fff1e9"
SANS = "'Helvetica Neue',Helvetica,Arial,sans-serif"
MONO = "'SF Mono',Menlo,Consolas,monospace"


def esc(s):
    return html.escape(str(s), quote=True)


def text(x, y, s, size=11, weight=400, fill=INK, anchor="start", mono=False, italic=False, spacing=None):
    fam = MONO if mono else SANS
    extra = ' font-style="italic"' if italic else ""
    if spacing is not None:
        extra += f' letter-spacing="{spacing}"'
    return (f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" font-weight="{weight}" '
            f'fill="{fill}" text-anchor="{anchor}"{extra}>{esc(s)}</text>')


def wrap(s, width):
    """Wrap to roughly `width` characters per line."""
    return textwrap.wrap(s, width=width, break_long_words=False) or [""]


def lines(x, y, s, width, size=11, lh=None, weight=400, fill=INK, anchor="start", mono=False):
    lh = lh or size * 1.3
    out = []
    for i, ln in enumerate(wrap(s, width)):
        out.append(text(x, y + i * lh, ln, size, weight, fill, anchor, mono))
    return "".join(out), len(wrap(s, width)) * lh


def rect(x, y, w, h, fill="#fff", stroke=LINE, sw=1.2, rx=8, dash=None):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>'


def line(x1, y1, x2, y2, stroke=SOFT, sw=1.4, dash=None, arrow=False, marker="a"):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    m = f' marker-end="url(#{marker})"' if arrow else ""
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{sw}"{d}{m}/>'


def path(d, stroke=SOFT, sw=1.4, dash=None, arrow=False, fill="none", marker="a"):
    dd = f' stroke-dasharray="{dash}"' if dash else ""
    m = f' marker-end="url(#{marker})"' if arrow else ""
    return f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{dd}{m}/>'


def circle(cx, cy, r, fill=SIG, stroke="none", sw=1):
    return f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'


def badge(cx, cy, n, fill=SIG, r=11):
    return circle(cx, cy, r, fill) + text(cx, cy + 4, n, 11.5, 700, "#fff", "middle")


def chip(x, y, s, fill=SIG, color="#fff", size=9, pad=6, weight=700):
    w = len(s) * size * 0.76 + pad * 2
    return (rect(x, y, w, size + 8, fill, "none", 0, 9) + text(x + w / 2, y + size + 1.5, s, size, weight, color, "middle", spacing=0.4)), w


def card(x, y, w, h, title, body, width_chars, fill="#fff", stroke=LINE, tcolor=INK, dash=None, size=10.5, tsize=12):
    """A rounded card with a bold title and wrapped body text."""
    out = [rect(x, y, w, h, fill, stroke, 1.4, 9, dash)]
    out.append(text(x + 12, y + 20, title, tsize, 700, tcolor))
    if body:
        b, _ = lines(x + 12, y + 38, body, width_chars, size, size * 1.32, 400, SOFT)
        out.append(b)
    return "".join(out)


def svg(w, h, body, label=""):
    defs = (
        '<defs>'
        f'<marker id="a" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{SOFT}"/></marker>'
        f'<marker id="o" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{SIG}"/></marker>'
        f'<marker id="r" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{RED}"/></marker>'
        '</defs>'
    )
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%" role="img" aria-label="{esc(label)}">'
            f'{defs}{body}</svg>')
