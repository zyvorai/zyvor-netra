// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllCLICommandsAgainstMock(t *testing.T) {
	t.Setenv("NETRA_CLI_HELP", "plain")

	srv := httptest.NewServer(http.HandlerFunc(mockNetraAPI))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	catalog := allCLICommands()
	if len(catalog) < 80 {
		t.Fatalf("catalog too small: %d (expected broad CLI coverage)", len(catalog))
	}

	for _, c := range catalog {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			base = srv.URL // defend against other tests / configOnce side effects
			args := append([]string(nil), c.Args...)
			if c.FileKind != "" {
				path := writeCLIFixture(t, c.FileKind)
				for i, a := range args {
					if a == "$FILE" {
						args[i] = path
					}
				}
			}
			if err := run(args); err != nil {
				t.Fatalf("netractl %s: %v", strings.Join(args, " "), err)
			}
		})
	}
}

func TestCLICommandCatalogUniqueNames(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range allCLICommands() {
		if c.Name == "" {
			t.Fatal("empty command name")
		}
		if seen[c.Name] {
			t.Fatalf("duplicate command name %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.Args) == 0 {
			t.Fatalf("%s: empty args", c.Name)
		}
	}
}

// TestDumpCLICommandsForRemote prints machine-readable catalog lines for
// scripts/ci-netractl-remote.sh. Always passes; output is the contract.
func TestDumpCLICommandsForRemote(t *testing.T) {
	for _, c := range allCLICommands() {
		mut, local, stream, opt := "0", "0", "0", "0"
		if c.Mutating {
			mut = "1"
		}
		if c.Local {
			local = "1"
		}
		if c.Streaming {
			stream = "1"
		}
		if c.Optional {
			opt = "1"
		}
		t.Logf("cli-command: %s|%s|%s|%s|%s|%s|%s", c.Name, mut, local, stream, opt, c.FileKind, strings.Join(c.Args, "\t"))
	}
}

func writeCLIFixture(t *testing.T, kind string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, kind+".json")
	var body []byte
	switch kind {
	case "policy":
		body = []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"ci","namespace":"default"},"spec":{"endpointSelector":{"matchLabels":{"app":"web"}},"egress":[{"toCIDR":["10.0.0.0/8"]}]}}`)
	case "intel":
		body = []byte("203.0.113.1\nmalicious.example.com\n")
	case "watchlist":
		body = []byte("10.0.0.1\napp.internal\n")
	case "explain":
		body = []byte(`{"items":[{"node":"ci","containers":[]}]}`)
	case "out":
		body = nil // export destination; create empty file path only
		path = filepath.Join(dir, "archive-out.json")
	case "scope":
		body = []byte(`{"mode":"selected","scopes":[{"namespace":"default"}]}`)
	default:
		t.Fatalf("unknown FileKind %q", kind)
	}
	if body != nil {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func mockNetraAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := r.URL.Path
	switch {
	case path == "/api/v1/status":
		_, _ = w.Write([]byte(`{"version":"ci","datapath":"ebpf","agents":1,"staleAgents":0,"ciliumEnabled":false,"fastPath":{"mode":"observe"}}`))
	case path == "/api/v1/features":
		_, _ = w.Write([]byte(`{"features":[{"id":"dns-detect","title":"DNS detect","scope":"agent","enabled":false,"source":"env"}]}`))
	case path == "/api/v1/ebpf/maps":
		_, _ = w.Write([]byte(`{"generatedAt":"2026-09-18T00:00:00Z","mode":"observe","revision":1,"pinRoot":"/sys/fs/bpf/netra","note":"ci","filledMaps":0,"emptyMaps":0,"totalEntries":0,"maps":[]}`))
	case path == "/api/v1/fleet":
		_, _ = w.Write([]byte(`{"nodes":[{"name":"ci","ready":true}]}`))
	case path == "/api/v1/lease":
		_, _ = w.Write([]byte(`{"active":false,"mode":"observe"}`))
	case path == "/api/v1/policies/plan":
		_, _ = w.Write([]byte(`{"plan":{"risk":"low"},"dryRun":{"passed":true},"receipt":{"token":"ci-receipt"}}`))
	case path == "/api/v1/policies/history/export":
		_, _ = w.Write([]byte(`{"schemaVersion":1,"exportedAt":"2026-09-18T00:00:00Z","revisions":[]}`))
	case strings.HasPrefix(path, "/api/v1/ai/"):
		_, _ = w.Write([]byte(`{"ok":true,"brief":"ci","answer":"ci","status":"ready"}`))
	case path == "/api/v1/agents":
		_, _ = io.WriteString(w, `{"items":[]}`)
	default:
		// Most list endpoints accept an empty object or array.
		if r.Method == http.MethodGet && (strings.Contains(path, "/export/") || strings.HasSuffix(path, "/report") || strings.Contains(path, "playbooks") || strings.Contains(path, "handoff")) {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		enc := json.NewEncoder(w)
		_ = enc.Encode(map[string]any{"ok": true, "path": path, "method": r.Method})
	}
}
