package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPlanAndApplyUsesReceipt(t *testing.T) {
	var applied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies/plan":
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"plan":{"risk":"low"},"dryRun":{"passed":true},"receipt":{"token":"receipt-1"}}`))
		case "/api/v1/policies/apply":
			if r.Header.Get("X-Netra-Plan-Token") != "receipt-1" {
				t.Fatalf("missing receipt header: %#v", r.Header)
			}
			applied = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	if err := planAndApply([]byte(`{"kind":"CiliumNetworkPolicy"}`), ""); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("apply was not called")
	}
}

func TestPlanAndApplyRequiresHighRiskConfirmation(t *testing.T) {
	var applyCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/policies/plan" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"plan":{"risk":"high"},"dryRun":{"passed":true},"receipt":{"token":"receipt-high"}}`))
			return
		}
		if r.URL.Path == "/api/v1/policies/apply" {
			applyCalls++
			if r.Header.Get("X-Netra-Confirm-Risk") != "high" {
				t.Fatalf("missing risk confirmation")
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)
	if err := planAndApply([]byte(`{"kind":"CiliumNetworkPolicy"}`), ""); err == nil {
		t.Fatal("expected high-risk confirmation error")
	}
	if applyCalls != 0 {
		t.Fatalf("apply called without confirmation: %d", applyCalls)
	}
	if err := planAndApply([]byte(`{"kind":"CiliumNetworkPolicy"}`), "high"); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatalf("expected one confirmed apply, got %d", applyCalls)
	}
}

func TestPolicyArchiveExportImport(t *testing.T) {
	archive := []byte(`{"schemaVersion":1,"exportedAt":"2026-09-11T00:00:00Z","revisions":[]}`)
	var imported bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policies/history/export":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(archive)
		case "/api/v1/policies/history/import":
			if r.Header.Get("X-Netra-Confirm-History-Replace") != "replace" {
				t.Fatalf("missing replace confirmation header")
			}
			if r.URL.Query().Get("mode") != "replace" {
				t.Fatalf("mode=%q", r.URL.Query().Get("mode"))
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != string(archive) {
				t.Fatalf("body=%s", body)
			}
			imported = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"imported":0,"mode":"replace"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	file := t.TempDir() + "/history.json"
	withArgs(t, "policy", "archive", "export", file)
	if err := policy(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != string(archive) {
		t.Fatalf("got=%s err=%v", got, err)
	}
	withArgs(t, "policy", "archive", "import", file, "--mode", "replace")
	if err := policy(); err != nil {
		t.Fatal(err)
	}
	if !imported {
		t.Fatal("import endpoint was not called")
	}
}

func TestEBPFDNSAndProcessCommands(t *testing.T) {
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/v1/ebpf/dns":
			if string(body) != `{"name":"telemetry.example.com"}` {
				t.Fatalf("dns body=%s", body)
			}
			seen["dns"] = true
		case "/api/v1/ebpf/process":
			if string(body) != `{"name":"curl"}` {
				t.Fatalf("process body=%s", body)
			}
			seen["process"] = true
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	withArgs(t, "ebpf", "dns", "add", "telemetry.example.com")
	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	withArgs(t, "ebpf", "process", "add", "curl")
	if err := ebpf(); err != nil {
		t.Fatal(err)
	}
	if !seen["dns"] || !seen["process"] {
		t.Fatalf("seen=%#v", seen)
	}
}

func TestInsightsRateCommands(t *testing.T) {
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path] = true
		if r.URL.Path == "/api/v1/insights/rate-baseline" && r.Method == http.MethodDelete && r.Header.Get("X-Netra-Confirm-Rate-Baseline-Clear") != "clear" {
			t.Fatalf("missing rate-baseline clear confirmation")
		}
		if strings.Contains(r.URL.Path, "rate") && r.URL.Query().Get("window") != "" && r.URL.Query().Get("window") != "5m" {
			t.Fatalf("window=%q", r.URL.Query().Get("window"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	useTestServer(t, srv.URL)

	for _, args := range [][]string{
		{"insights", "rates", "5m"},
		{"insights", "rate-drift", "5m"},
		{"insights", "exposure", "5m"},
		{"insights", "remediations", "5m"},
		{"insights", "rate-baseline", "capture", "5m"},
		{"insights", "rate-baseline", "clear"},
	} {
		withArgs(t, args...)
		if err := insightCmd(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if !seen["GET /api/v1/insights/rates"] || !seen["POST /api/v1/insights/rate-baseline"] || !seen["DELETE /api/v1/insights/rate-baseline"] {
		t.Fatalf("seen=%#v", seen)
	}
}
