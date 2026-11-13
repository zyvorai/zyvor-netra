// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package ainet

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestLookupLongestSuffix(t *testing.T) {
	e, ok := lookup(DefaultCatalog(), "api.openai.com")
	if !ok || e.Label != "OpenAI API" {
		t.Fatalf("got %+v ok=%v", e, ok)
	}
	e, ok = lookup(DefaultCatalog(), "foo.smithery.ai")
	if !ok || e.Category != CatMCP {
		t.Fatalf("got %+v ok=%v", e, ok)
	}
	if _, ok := lookup(DefaultCatalog(), "example.com"); ok {
		t.Fatal("unexpected match")
	}
}

func TestMatchSNI(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node:        "n1",
			TLSMetadata: []models.TLSMetadataStat{{SNI: "api.anthropic.com", Handshakes: 3, Namespace: "ns", Pod: "p"}},
		},
	}}
	res := Match(agents, nil, 50)
	if res.Count != 1 || res.Hits[0].Kind != "sni" {
		t.Fatalf("%+v", res)
	}
	ents := DenyEntries(res.Hits)
	if len(ents) != 1 || ents[0].Type != "sni" {
		t.Fatalf("%+v", ents)
	}
}

func TestCatalogSuffixes(t *testing.T) {
	cases := []struct {
		host string
		cat  Category
	}{
		{"foo.api.nvidia.com", CatLLMSaaS},
		{"x.inference.azure.com", CatLLMSaaS},
		{"api.gemini.google.com", CatLLMSaaS},
		{"gpu.runpod.io", CatAIInfra},
		{"mcp.github.com", CatMCP},
		{"api.githubcopilot.com", CatMCP},
		{"ide.windsurf.com", CatAIInfra},
		{"api.tabnine.com", CatAIInfra},
		{"files.oaiusercontent.com", CatAIInfra},
		{"tenant.copilotstudio.microsoft.com", CatMCP},
		{"x.bedrock-agent-runtime.amazonaws.com", CatAIInfra},
		{"api.voyageai.com", CatLLMSaaS},
		{"api.elevenlabs.io", CatAIInfra},
		{"gemini.google.com", CatLLMSaaS},
	}
	for _, c := range cases {
		e, ok := lookup(DefaultCatalog(), c.host)
		if !ok || e.Category != c.cat {
			t.Fatalf("%s: got %+v ok=%v want %s", c.host, e, ok, c.cat)
		}
	}
}
