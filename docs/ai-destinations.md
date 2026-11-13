# AI / MCP destination awareness

Observe (and optionally lease-deny) known GenAI / MCP SaaS destinations from
existing SNI, HTTP Host, and DNS metadata. **No prompts, bodies, or Secrets.**

Distinct from Netra’s own MCP server (`docs/mcp-integration.md`).

```text
GET  /api/v1/ebpf/ai-destinations
POST /api/v1/ebpf/ai-destinations/deny   # leased; X-Netra-Confirm-Risk: high
```

```bash
netractl ebpf ai-destinations
```

Catalog: `internal/ainet` (OpenAI, Anthropic, Azure OpenAI, Cohere, Mistral,
Groq, Hugging Face, Cursor, common MCP SaaS hostnames, …). Longest suffix wins.

Deny apply requires `mode=enforce` + active lease + confirm header; writes
SNI deny entries for currently observed hosts only.

**UX:** Surfaces → AI destinations (board id `ainet`). MCP resource `netra://ebpf/ai-destinations` and tool `netra_ebpf_ai_destinations`. Parent catalog:
[`p0-p5-surfaces.md`](p0-p5-surfaces.md).

See also: [competitive-quantum.md](competitive-quantum.md), [l7-metadata.md](l7-metadata.md),
[buyers guide](sales/buyers-guide.md).
