# Social assets

| File | What it is | Rebuild |
|---|---|---|
| `netra-share-card.png` | 1200×630 card: the README hero and the website's social preview (`website/docusaurus.config.ts` serves this folder as static files) | Raster artwork with no source in the repository. Its licence pill and version were redrawn in place for 0.28.0 (Apache 2.0 and v0.14 before); when the version moves, redraw the footer text the same way |
| `netra-social-card.html` / `.jpg` | 1600×900 (16:9) card for LinkedIn and X, in the brochure's look: the traffic-drop story in five steps | `./docs/social/build-social-card.sh` (Google Chrome and macOS `sips`, nothing to install) |
| `readme/*.html` | Three cards used by the README: `readme-how-it-works.jpg`, `readme-capabilities.jpg`, `readme-lease-safety.jpg` (written to `docs/ux/`) | `./docs/social/readme/build.sh` (Google Chrome and macOS `sips`, nothing to install) |
| `netra-field-sheet.html` / `.pdf` | One-page field sheet | Print `netra-field-sheet.html` to PDF with Chrome |

Every claim on the social card is one the [product brochure](../sales/brochure/README.md) already sources.
Licence wording follows `LICENSE`: the Zyvor Production Licence v2.0; a commercial license is required for production use.

The dark hero (`netra-hero-dark.html` / `.jpg`) carries a dedication to Kerala and Thiruvananthapuram (English and Malayalam), a gold kasavu border along the bottom edge, and Malayalam letters mixed into the code rain. The README hero and the website's social preview both use it.
The hero eye is drawn Kerala style: heavy kohl with a winged tail, a gold-ringed iris carrying MEKHA in hex (`4D 45 4B 48 41`) all the way round, a bindi, and a gold line-art backwater scene (palms and a kettuvallam houseboat) along the left.
