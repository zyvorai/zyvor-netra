# Social assets

| File | What it is | Rebuild |
|---|---|---|
| `netra-share-card.png` | 1200×630 card: the README hero and the website's social preview (`website/docusaurus.config.ts` serves this folder as static files) | Raster artwork with no source in the repository. Its licence pill and version were redrawn in place for 0.28.0 (Apache 2.0 and v0.14 before); when the version moves, redraw the footer text the same way |
| `netra-social-card.html` / `.jpg` | 1600×900 (16:9) card for LinkedIn and X, in the brochure's look: the traffic-drop story in five steps | `./docs/social/build-social-card.sh` (Google Chrome and macOS `sips`, nothing to install) |
| `readme/*.html` | Three cards used by the README: `readme-how-it-works.jpg`, `readme-capabilities.jpg`, `readme-lease-safety.jpg` (written to `docs/ux/`) | `./docs/social/readme/build.sh` (Google Chrome and macOS `sips`, nothing to install) |
| `netra-field-sheet.html` / `.pdf` | One-page field sheet | Print `netra-field-sheet.html` to PDF with Chrome |

Every claim on the social card is one the [product brochure](../sales/brochure/README.md) already sources.
Licence wording follows `LICENSE`: the Zyvor Production License v1.0; a commercial license is required for production use.
