// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package gitops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadManifestsReadsAndConvertsYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: a\n  namespace: prod\nspec:\n  endpointSelector:\n    matchLabels:\n      app: a\n")
	writeFile(t, dir, "b.yml", "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: b\n")
	writeFile(t, dir, "readme.txt", "not a manifest")

	manifests, loadErrors := LoadManifests(dir)
	if len(loadErrors) != 0 {
		t.Fatalf("loadErrors=%v", loadErrors)
	}
	if len(manifests) != 2 {
		t.Fatalf("manifests=%d, want 2 (readme.txt must be skipped)", len(manifests))
	}
	if manifests[0].Path != "a.yaml" || manifests[1].Path != "b.yml" {
		t.Fatalf("expected sorted order, got %s then %s", manifests[0].Path, manifests[1].Path)
	}
	var doc map[string]any
	if err := json.Unmarshal(manifests[0].JSON, &doc); err != nil {
		t.Fatalf("expected valid JSON conversion: %v", err)
	}
	meta, _ := doc["metadata"].(map[string]any)
	if meta["name"] != "a" || meta["namespace"] != "prod" {
		t.Fatalf("metadata=%#v", meta)
	}
}

func TestLoadManifestsMultiDocFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "multi.yaml", "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: a\n---\napiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: b\n")
	manifests, loadErrors := LoadManifests(dir)
	if len(loadErrors) != 0 {
		t.Fatalf("loadErrors=%v", loadErrors)
	}
	if len(manifests) != 2 {
		t.Fatalf("manifests=%d, want 2 from one multi-doc file", len(manifests))
	}
}

func TestLoadManifestsBadFileDoesNotBlockOthers(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.yaml", "{ this is not: valid: yaml: [")
	writeFile(t, dir, "good.yaml", "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: good\n")
	manifests, loadErrors := LoadManifests(dir)
	if len(manifests) != 1 || manifests[0].Path != "good.yaml" {
		t.Fatalf("manifests=%#v, want just good.yaml", manifests)
	}
	if len(loadErrors) != 1 {
		t.Fatalf("loadErrors=%v, want exactly 1 entry for bad.yaml", loadErrors)
	}
}

func TestLoadManifestsMissingDirReturnsError(t *testing.T) {
	manifests, loadErrors := LoadManifests(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(manifests) != 0 || len(loadErrors) == 0 {
		t.Fatalf("manifests=%v loadErrors=%v, want empty manifests and a load error", manifests, loadErrors)
	}
}
