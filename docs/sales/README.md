# Netra buyer resources

Customer-facing Netra materials (Zyvor perspective visual system).

| Document | Formats | Description |
|----------|---------|-------------|
| **Buyers guide** | [Markdown](./buyers-guide.md) | Evaluation narrative: who should buy, P0–P5 observe surfaces, how Netra works, checklist |
| **Product Perspective** | [PDF](./Zyvor-Netra-Product-Perspective.pdf) · [PPTX](./Zyvor-Netra-Product-Perspective.pptx) | Executive deck (Netra-only) including Surfaces / encrypted-traffic boards |
| **Product Brochure** | [PDF](./Zyvor-Netra-Product-Brochure.pdf) (17 pages, [source](./brochure/)) | How eBPF does it, a step-by-step traffic-drop scenario with diagrams (detect, capture the node's packets, contain), the newest kernel sensors, privacy boundaries, access and export, deploy/upgrade/HA and how it is tested, plus PacketWolf suite placement and a buying checklist |
| **Enterprise pricing** | [PDF](./Zyvor-Netra-Enterprise-Pricing.pdf) · [JPEG sheets](./enterprise-pricing.md) (5 sheets, [source](./enterprise-pricing/), `build.sh` rebuilds the JPEGs and the PDF) | Packaging, editions, services, and ship plan. Community is free for evaluation and non-production use under the Zyvor Production License; production use needs a commercial license |

Technical depth for the same features: [`../p0-p5-surfaces.md`](../p0-p5-surfaces.md).

## Download on the web

Same binary files are published on GitHub Pages:

- https://zyvorai.github.io/netra/resources
- https://zyvorai.github.io/netra/sales/

(The Pages copies live under `website/static/sales/` so URLs stay under `/sales/`.)

The buyers guide is also downloadable from Resources as `/sales/buyers-guide.md`
(keep `docs/sales/` and `website/static/sales/` in sync).

## Browse on GitHub

https://github.com/zyvorai/zyvor-netra/tree/main/docs/sales
