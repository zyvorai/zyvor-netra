// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package ainet

import (
	"strings"

	"github.com/zyvorai/netra/internal/intel"
	"github.com/zyvorai/netra/internal/models"
)

// Category classifies a matched destination without reading payloads.
type Category string

const (
	CatLLMSaaS Category = "llm_saas"
	CatMCP     Category = "mcp_saas"
	CatAIInfra Category = "ai_infra"
)

// CatalogEntry is one known GenAI / MCP destination hostname suffix.
type CatalogEntry struct {
	Suffix   string   `json:"suffix"`
	Category Category `json:"category"`
	Label    string   `json:"label"`
}

// DefaultCatalog is a metadata-only hostname list (SNI / HTTP Host / DNS).
// No prompts, bodies, or Secrets are inspected.
func DefaultCatalog() []CatalogEntry {
	return []CatalogEntry{
		{Suffix: "openai.com", Category: CatLLMSaaS, Label: "OpenAI"},
		{Suffix: "api.openai.com", Category: CatLLMSaaS, Label: "OpenAI API"},
		{Suffix: "chatgpt.com", Category: CatLLMSaaS, Label: "ChatGPT"},
		{Suffix: "anthropic.com", Category: CatLLMSaaS, Label: "Anthropic"},
		{Suffix: "api.anthropic.com", Category: CatLLMSaaS, Label: "Anthropic API"},
		{Suffix: "claude.ai", Category: CatLLMSaaS, Label: "Claude"},
		{Suffix: "googleapis.com", Category: CatAIInfra, Label: "Google APIs"},
		{Suffix: "generativelanguage.googleapis.com", Category: CatLLMSaaS, Label: "Google Generative Language"},
		{Suffix: "openai.azure.com", Category: CatLLMSaaS, Label: "Azure OpenAI"},
		{Suffix: "cognitiveservices.azure.com", Category: CatAIInfra, Label: "Azure Cognitive Services"},
		{Suffix: "api.cohere.ai", Category: CatLLMSaaS, Label: "Cohere"},
		{Suffix: "api.cohere.com", Category: CatLLMSaaS, Label: "Cohere"},
		{Suffix: "api.mistral.ai", Category: CatLLMSaaS, Label: "Mistral"},
		{Suffix: "api.groq.com", Category: CatLLMSaaS, Label: "Groq"},
		{Suffix: "api.together.xyz", Category: CatLLMSaaS, Label: "Together"},
		{Suffix: "api.fireworks.ai", Category: CatLLMSaaS, Label: "Fireworks"},
		{Suffix: "api.perplexity.ai", Category: CatLLMSaaS, Label: "Perplexity"},
		{Suffix: "api.deepseek.com", Category: CatLLMSaaS, Label: "DeepSeek"},
		{Suffix: "huggingface.co", Category: CatAIInfra, Label: "Hugging Face"},
		{Suffix: "api.huggingface.co", Category: CatAIInfra, Label: "Hugging Face API"},
		{Suffix: "replicate.com", Category: CatAIInfra, Label: "Replicate"},
		{Suffix: "api.replicate.com", Category: CatAIInfra, Label: "Replicate API"},
		{Suffix: "cursor.sh", Category: CatAIInfra, Label: "Cursor"},
		{Suffix: "api2.cursor.sh", Category: CatAIInfra, Label: "Cursor API"},
		{Suffix: "mcp.openai.com", Category: CatMCP, Label: "OpenAI MCP"},
		{Suffix: "mcp.anthropic.com", Category: CatMCP, Label: "Anthropic MCP"},
		{Suffix: "smithery.ai", Category: CatMCP, Label: "Smithery MCP"},
		{Suffix: "mcp.pipedream.com", Category: CatMCP, Label: "Pipedream MCP"},
		{Suffix: "api.x.ai", Category: CatLLMSaaS, Label: "xAI"},
		{Suffix: "x.ai", Category: CatLLMSaaS, Label: "xAI"},
		{Suffix: "api.moonshot.cn", Category: CatLLMSaaS, Label: "Moonshot"},
		{Suffix: "api.grok.x.ai", Category: CatLLMSaaS, Label: "Grok"},
		{Suffix: "ollama.com", Category: CatAIInfra, Label: "Ollama"},
		{Suffix: "api.ollama.com", Category: CatAIInfra, Label: "Ollama API"},
		{Suffix: "openrouter.ai", Category: CatLLMSaaS, Label: "OpenRouter"},
		{Suffix: "api.openrouter.ai", Category: CatLLMSaaS, Label: "OpenRouter API"},
		{Suffix: "api.cerebras.ai", Category: CatLLMSaaS, Label: "Cerebras"},
		{Suffix: "api.sambanova.ai", Category: CatLLMSaaS, Label: "SambaNova"},
		{Suffix: "bedrock.amazonaws.com", Category: CatAIInfra, Label: "AWS Bedrock"},
		{Suffix: "bedrock-runtime.amazonaws.com", Category: CatAIInfra, Label: "AWS Bedrock Runtime"},
		{Suffix: "aiplatform.googleapis.com", Category: CatAIInfra, Label: "Google Vertex AI"},
		{Suffix: "notebooks.googleapis.com", Category: CatAIInfra, Label: "Google Notebooks"},
		{Suffix: "mcp.smithery.ai", Category: CatMCP, Label: "Smithery MCP"},
		{Suffix: "composio.dev", Category: CatMCP, Label: "Composio"},
		{Suffix: "api.composio.dev", Category: CatMCP, Label: "Composio API"},
		{Suffix: "zapier.com", Category: CatMCP, Label: "Zapier"},
		{Suffix: "mcp.zapier.com", Category: CatMCP, Label: "Zapier MCP"},
		{Suffix: "cursor.com", Category: CatAIInfra, Label: "Cursor"},
		{Suffix: "api.cursor.com", Category: CatAIInfra, Label: "Cursor API"},
		{Suffix: "api.nvidia.com", Category: CatLLMSaaS, Label: "NVIDIA NIM"},
		{Suffix: "inference.azure.com", Category: CatLLMSaaS, Label: "Azure AI Inference"},
		{Suffix: "ai.azure.com", Category: CatAIInfra, Label: "Azure AI"},
		{Suffix: "api.gemini.google.com", Category: CatLLMSaaS, Label: "Google Gemini API"},
		{Suffix: "bard.google.com", Category: CatLLMSaaS, Label: "Google Bard"},
		{Suffix: "modal.com", Category: CatAIInfra, Label: "Modal"},
		{Suffix: "runpod.io", Category: CatAIInfra, Label: "RunPod"},
		{Suffix: "vast.ai", Category: CatAIInfra, Label: "Vast.ai"},
		{Suffix: "lambda.ai", Category: CatAIInfra, Label: "Lambda"},
		{Suffix: "mcp.github.com", Category: CatMCP, Label: "GitHub MCP"},
		{Suffix: "api.githubcopilot.com", Category: CatMCP, Label: "GitHub Copilot"},
		{Suffix: "cline.bot", Category: CatMCP, Label: "Cline"},
		{Suffix: "windsurf.com", Category: CatAIInfra, Label: "Windsurf"},
		{Suffix: "codeium.com", Category: CatAIInfra, Label: "Codeium"},
		{Suffix: "tabnine.com", Category: CatAIInfra, Label: "Tabnine"},
	}
}

// Hit is one observe-only match of catalog hostname against live metadata.
type Hit struct {
	Category  Category `json:"category"`
	Label     string   `json:"label"`
	Host      string   `json:"host"`
	Kind      string   `json:"kind"` // sni | http-host | dns
	Node      string   `json:"node,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Pod       string   `json:"pod,omitempty"`
	Packets   uint64   `json:"packets,omitempty"`
	Blocked   uint64   `json:"blocked,omitempty"`
}

// Result is the JSON envelope for GET /api/v1/ebpf/ai-destinations.
type Result struct {
	Hits    []Hit `json:"hits"`
	Count   int   `json:"count"`
	Capped  bool  `json:"capped"`
	Catalog int   `json:"catalogSize"`
}

const MaxHits = 500

// Match scans agent TLS/HTTP/DNS metadata for catalog hostnames.
func Match(agents []models.AgentStatus, catalog []CatalogEntry, limit int) Result {
	if limit <= 0 || limit > MaxHits {
		limit = MaxHits
	}
	if len(catalog) == 0 {
		catalog = DefaultCatalog()
	}
	out := Result{Hits: []Hit{}, Catalog: len(catalog)}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, t := range a.TLSMetadata {
			if len(out.Hits) >= limit {
				out.Capped = true
				out.Count = len(out.Hits)
				return out
			}
			if e, ok := lookup(catalog, t.SNI); ok {
				out.Hits = append(out.Hits, Hit{
					Category: e.Category, Label: e.Label, Host: t.SNI, Kind: "sni",
					Node: a.Node, Namespace: t.Namespace, Pod: t.Pod,
					Packets: t.Handshakes, Blocked: t.Blocked,
				})
			}
		}
		for _, h := range a.HTTPMetadata {
			if len(out.Hits) >= limit {
				out.Capped = true
				out.Count = len(out.Hits)
				return out
			}
			if e, ok := lookup(catalog, h.Host); ok {
				out.Hits = append(out.Hits, Hit{
					Category: e.Category, Label: e.Label, Host: h.Host, Kind: "http-host",
					Node: a.Node, Namespace: h.Namespace, Pod: h.Pod,
					Packets: h.Requests,
				})
			}
		}
		for _, d := range a.DNSHealth {
			if len(out.Hits) >= limit {
				out.Capped = true
				out.Count = len(out.Hits)
				return out
			}
			if e, ok := lookup(catalog, d.Name); ok {
				out.Hits = append(out.Hits, Hit{
					Category: e.Category, Label: e.Label, Host: d.Name, Kind: "dns",
					Node: a.Node, Namespace: d.Namespace, Pod: d.Pod,
					Packets: d.Queries, Blocked: d.Failures,
				})
			}
		}
	}
	out.Count = len(out.Hits)
	out.Capped = out.Count >= limit
	return out
}

func lookup(catalog []CatalogEntry, host string) (CatalogEntry, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return CatalogEntry{}, false
	}
	var best CatalogEntry
	bestLen := -1
	for _, e := range catalog {
		suf := strings.ToLower(strings.TrimSuffix(e.Suffix, "."))
		if h == suf || strings.HasSuffix(h, "."+suf) {
			if len(suf) > bestLen {
				best = e
				bestLen = len(suf)
			}
		}
	}
	if bestLen < 0 {
		return CatalogEntry{}, false
	}
	return best, true
}

// DenyEntries turns unique matched hosts into SNI deny-import entries
// (egress). Operator must still lease-enforce and confirm apply.
func DenyEntries(hits []Hit) []intel.Entry {
	seen := map[string]bool{}
	var out []intel.Entry
	for _, h := range hits {
		host := strings.ToLower(strings.TrimSuffix(h.Host, "."))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, intel.Entry{Type: "sni", Value: host, Direction: "egress"})
	}
	return out
}
