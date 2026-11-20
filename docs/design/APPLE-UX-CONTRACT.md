# Netra UX contract — apple.com

Netra's dashboard (`web/`) and docs site (`website/`) follow one apple.com-style
contract, adapted from Machina's `docs/design/APPLE-UX-CONTRACT.md` and
`DAYLIGHT-CONTRACT.md`. Netra keeps its own identity: observe-first,
diagnostic, quiet until something deviates.

Tokens live in `web/src/styles.css` (`:root` = Apple light, the default;
`[data-theme="dark"]` = opt-in). Primitives live in
`web/src/styles/apple-story.css`. The docs site reuses the same values in
`website/src/css/custom.css`.

## Surface tiers

| Tier | Netra pages | Density | Layout |
|---|---|---|---|
| **Story** | Login, Overview | Very low | `.apple-section` → eyebrow, `.apple-display`, `.apple-lede`, one CTA; `.apple-metric-band` instead of a tile grid |
| **Browse** | Connections, Flows, Drops, Workloads, Talkers, Traffic, Audit, Incidents, Scorecard | Medium | `PageHero` + `Toolbar` + `TableWrap` (hairline table) |
| **Work** | Firewall (EBPF), Policies, Capture, Congestion Map, Report, Surfaces | High | `.card` panels, tokens only |
| **Immersive** | Capture terminal, PodExec, PodLogs, VMVnc | Full | Stays dark in both themes; type still uses `--text-*` / `--terminal-*` |

## Tokens

| Token | Light (default) | Dark |
|---|---|---|
| `--bg-page` | `#ffffff` | `#000000` |
| `--surface-1` (card) | `#ffffff` + hairline | `#1d1d1f` |
| `--text-primary` | `#1d1d1f` | `#f5f5f7` |
| `--text-secondary` | `#6e6e73` | `#a1a1a6` |
| `--text-tertiary` | `#86868b` | `#86868b` |
| `--apple-blue` (CTA, focus) | `#0071e3` | `#0071e3` |
| `--apple-link` | `#0066cc` | `#2997ff` |

## Type scale

Headings, figures and body copy read these tokens (`:root` in `web/src/styles.css`); do not
add raw `px` font sizes above 17px.

| Token | Value | Used by |
|---|---|---|
| `--fs-h1` | `clamp(24px, 2.6vw, 34px)` | `.hero h1`, `.page-hero h1`, `.apple-display`, login title |
| `--fs-h2` | `clamp(20px, 1.8vw, 24px)` | `.card h2`, Overview chapter headings, login card |
| `--fs-h3` | `17px` | `.card-title`, `.card h3`, `.list-empty h3` |
| `--fs-figure` | `clamp(18px, 1.6vw, 24px)` | `.metrics b`, `.apple-metric-band b`, Overview pulse |
| `--fs-lede` | `16px` | hero/page-hero/login lede, `.apple-lede` |
| `--fs-body` | `15px` | `body`, `.card p`, buttons |
| `--fs-link` | `15px` | `.apple-text-link`, Overview links |

Page heroes are compact titles, not posters: the data starts within the first screen. On the
Overview, the live datapath panel — not the headline — is the big moment.

## Laws

1. **Elevation runs up.** Dark: page `#000` → panel `#1d1d1f` → card lighter → popover lightest. Light: white page, white card with a hairline, popover with a soft shadow. A grey panel on a white page is a bug.
2. **Color is deviation.** Nominal values are graphite. Blue means intent (CTA, link, focus). Red/amber/green only when a value really deviates or is confirmed good.
3. **One primary action per view**, `.primary` blue pill. Everything else is secondary or ghost.
4. **No hard-coded hex or rgba in components or page CSS.** Use tokens; define new ones in `styles.css`.
5. **Read-only surfaces stay read-only.** A redesign must not add mutating controls to AI, netlink or BPF-inventory views (see `AGENTS.md`).

## Load-bearing markup (tests depend on it)

- Login heading text `Sign in.` and the `role="alert"` error.
- Overview metrics: `<div><span>label</span><b>value</b></div>` (label `node agents`).
- Nav: the `Investigate` region label and `Connections` button name; theme toggle aria-labels `Switch to light mode` / `Switch to dark mode`.
- `data-theme` on `<html>`; default is `light`. A stored `netra-theme` wins.

## Author checklist

1. Pick the tier first.
2. Story: one composition, no card grid.
3. Browse: `Toolbar` + `TableWrap`; search uses `.input-field`.
4. Empty lists get a title, a sentence, and a next action (`ListEmpty`); loading shows a skeleton, not blank space.
5. Check light and dark at 1440px and 390px; no horizontal scroll at 390px.
