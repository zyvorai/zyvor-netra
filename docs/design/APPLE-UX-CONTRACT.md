# Netra UX contract — apple.com

Netra's dashboard (`web/`) and docs site (`website/`) follow an apple.com-style
contract, adapted from Machina's `docs/design/APPLE-UX-CONTRACT.md` and
`DAYLIGHT-CONTRACT.md`. Netra keeps its own identity: observe-first,
diagnostic, quiet until something deviates.

Tokens live in `web/src/styles.css` (`:root` = light, `:root[data-theme="dark"]` =
dark; the terminal surfaces take the dark set in both). Primitives live in
`web/src/styles/apple-story.css`. The docs site keeps its own values in
`website/src/css/custom.css`.

## Themes

Light, Dark and **System** (the default), chosen from the Appearance menu
(`ThemeMenu`, in the navigation bar and on the sign-in page) and stored in
`localStorage['netra-appearance']`. `web/public/theme-init.js` sets
`<html data-theme>` before first paint; it is a file because the controller's
Content-Security-Policy is `script-src 'self'`. `web/src/theme.ts` keeps it in
step, including live operating-system changes. A `netra-theme=dark` stored by an
earlier release is kept; its `light` was written automatically and means System.

## Surface tiers

| Tier | Netra pages | Density | Layout |
|---|---|---|---|
| **Story** | Login, Overview | Very low | `.apple-section` → eyebrow, `.apple-display`, `.apple-lede`, one CTA; `.apple-metric-band` instead of a tile grid |
| **Browse** | Connections, Flows, Drops, Workloads, Talkers, Traffic, Audit, Incidents, Scorecard | Medium | `PageHero` + `Toolbar` + `TableWrap` (hairline table) |
| **Work** | Firewall (EBPF), Policies, Capture, Congestion Map, Report, Surfaces | High | `.card` panels, tokens only |
| **Immersive** | Capture terminal, PodExec, PodLogs, VMVnc | Full | Stays dark in both themes; type still uses `--text-*` / `--terminal-*` |

## Tokens

| Token | Light | Dark |
|---|---|---|
| `--bg-page` | `#f5f5f7` | `#000000` |
| `--surface-1` (card) | `#ffffff` + hairline | `#1d1d1f` |
| `--bg-elevated-2` (inset) | `#f5f5f7` | `#2a2a2c` |
| `--text-primary` | `#1d1d1f` | `#f5f5f7` |
| `--text-secondary` | `#515154` | `#b4b4b9` |
| `--text-tertiary` | `#636368` | `#a1a1a6` |
| `--apple-blue` (fill under white text, focus) | `#0071e3` | `#0071e3` |
| `--apple-link` (blue text) | `#005cb9` | `#4da3ff` |
| `--danger` / `--danger-fill` | `#bf001a` / `#bf001a` | `#ff7a73` / `#c4001a` |

Solid fills that carry white text use `--apple-blue` or `--danger-fill`. Bright
accents (`--accent-*`) are for dots, strokes and tints; text uses
`--accent-*-text`. Text tokens meet WCAG AA on every surface and tint, so do not
fade text with `opacity`.

## Shape

18px flat cards with a hairline edge; pill buttons; 12px inputs with a visible
edge. The navigation bar is 52px, sticky, translucent and blurred (two rows below
900px); menus use the same material. Focus is a 2px ring on `:focus-visible`.
All animation stops under `prefers-reduced-motion`. System fonts only: no
webfont downloads.

## Type scale

Headings, figures and body copy read these tokens (`:root` in `web/src/styles.css`); do not
add raw `px` font sizes above 18px.

| Token | Value | Used by |
|---|---|---|
| `--fs-h1` | `clamp(34px, 4.4vw, 52px)` | `.hero h1`, `.page-hero h1`, `.apple-display`, login title |
| `--fs-h2` | `clamp(21px, 1.9vw, 26px)` | `.card h2`, Overview chapter headings, login card |
| `--fs-h3` | `18px` | `.card-title`, `.card h3`, `.list-empty h3` |
| `--fs-figure` | `clamp(21px, 2vw, 30px)` | `.metrics b`, `.apple-metric-band b`, Overview pulse |
| `--fs-lede` | `clamp(16px, 1.4vw, 19px)` | hero/page-hero/login lede, `.apple-lede` |
| `--fs-body` | `15px` | `body`, `.card p`, buttons |
| `--fs-link` | `15px` | `.apple-text-link`, Overview links |

Page titles are large and tight, with generous space, but the data still starts within the first
screen. On the Overview, the live datapath panel — not the headline — is the big moment.

## Laws

1. **Elevation runs up.** Dark: page `#000` → card `#1d1d1f` → inset and popover lighter. Light: `#f5f5f7` page, white card with a hairline, popover with a soft shadow. Cards are flat: no gradients, glows or per-page tints.
2. **Color is deviation.** Nominal values are graphite. Blue means intent (CTA, link, focus). Red/amber/green only when a value really deviates or is confirmed good.
3. **One primary action per view**, `.primary` blue pill. Everything else is secondary or ghost.
4. **No hard-coded hex or rgba in components or page CSS.** Use tokens; define new ones in `styles.css`.
5. **Read-only surfaces stay read-only.** A redesign must not add mutating controls to AI, netlink or BPF-inventory views (see `AGENTS.md`).

## Load-bearing markup (tests depend on it)

- Login heading text `Sign in.` and the `role="alert"` error.
- Overview metrics: `<div><span>label</span><b>value</b></div>` (label `node agents`).
- Nav: the `Investigate` region label and `Connections` button name; the Appearance button's aria-label `Appearance: <Light|Dark|System>` (`data-testid="theme-toggle"`) and its `menuitemradio` items.
- `data-theme` on `<html>` is the painted theme (`light` or `dark`). A stored `netra-appearance` choice wins over the system.

## Author checklist

1. Pick the tier first.
2. Story: one composition, no card grid.
3. Browse: `Toolbar` + `TableWrap`; search uses `.input-field`.
4. Empty lists get a title, a sentence, and a next action (`ListEmpty`); loading shows a skeleton, not blank space.
5. Check light and dark at 1440px and 390px; no horizontal scroll at 390px. Anything that scrolls on its own is keyboard focusable.
