# Copilot instructions for Netra

Follow `AGENTS.md` and `CONTRIBUTING.md`.

Netra is observe-first eBPF observability. Do not propose changes that
collect payloads, write Cilium-owned maps, or auto-apply NetworkPolicy.
AI features (`internal/ai`, `/api/v1/ai/*`) are read-only summaries of
data Netra already computed. Optional LLM rewrite is env-gated and must
remain stdlib HTTP, not a vendor SDK.
